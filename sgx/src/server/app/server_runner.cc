/*
 Copyright (c) 2022 Haobin Chen
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <server/app/server_runner.hh>

#include <thread>
#include <atomic>
#include <fstream>
#include <sstream>
#include <cmath>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/bin_to_hex.h>
#include <sgx_uae_launch.h>
#include <sgx_uae_epid.h>
#include <sgx_uae_quote_ex.h>
#include <sgx_ukey_exchange.h>

#include <configs.hh>
#include <utils.hh>
#include <service_provider/service_provider.h>
#include <app/basic_models.hh>
#include <enclave/enclave_u.h>

std::atomic_bool server_running;

// This function is used to read the key pair from the file.
static std::string read_keycert(const std::string& path) {
  std::ifstream file(path, std::ifstream::in);
  std::ostringstream oss;

  if (file.good()) {
    oss << file.rdbuf();
    file.close();
  }
  return oss.str();
}

static void print_oram_config(const OramConfiguration& oram_config) {
  logger->info("ORAM Configuration:");
  logger->info("  way: {}", oram_config.way);
  logger->info("  number: {}", oram_config.number);
  logger->info("  bucket_size: ", oram_config.bucket_size);
  logger->info("  type: {}", oram_config.type);
  logger->info("  constant: {}", oram_config.constant);
  logger->info("  round: {}", oram_config.round);
  logger->info("  level: {}", oram_config.level);
  logger->info("  oram_type: {}", oram_config.oram_type);
}

// This function is dedicated to the assembly of message 2!!!
static void assemble_message(const oram::Message2* message,
                             sgx_ra_msg2_t** const msg2) {
  const uint32_t size = message->size();
  // Allocate memory for the message 2.
  sgx_ra_msg2_t* p_ra_message2 = nullptr;
  p_ra_message2 = (sgx_ra_msg2_t*)malloc(size + sizeof(sgx_ra_msg2_t));

  // Prepare the quote.
  uint8_t pubkey_gx[32];
  uint8_t pubkey_gy[32];
  sgx_ec256_signature_t signature_gb_ga;
  sgx_spid_t spid;

  // Copy the data from the message.
  for (size_t i = 0; i < 32; i++) {
    pubkey_gx[i] = message->public_key_gx(i);
    pubkey_gy[i] = message->public_key_gy(i);
  }
  for (size_t i = 0; i < 16; i++) {
    spid.id[i] = message->spid(i);
  }
  for (size_t i = 0; i < 8; i++) {
    signature_gb_ga.x[i] = message->signature_x(i);
    signature_gb_ga.y[i] = message->signature_y(i);
  }

  // Copy the data to the pointer.
  memcpy(&p_ra_message2->g_b.gx, &pubkey_gx, sizeof(pubkey_gx));
  memcpy(&p_ra_message2->g_b.gy, &pubkey_gy, sizeof(pubkey_gy));
  memcpy(&p_ra_message2->sign_gb_ga, &signature_gb_ga, sizeof(signature_gb_ga));
  memcpy(&p_ra_message2->spid, &spid, sizeof(spid));

  p_ra_message2->quote_type = static_cast<uint16_t>(message->quote_type());
  p_ra_message2->kdf_id = message->cmac_kdf_id();

  uint8_t smac[16];
  for (size_t i = 0; i < 16; i++) {
    smac[i] = message->smac(i);
  }
  memcpy(&p_ra_message2->mac, &smac, sizeof(smac));

  p_ra_message2->sig_rl_size = message->size_sigrl();
  uint8_t* sigrl = (uint8_t*)malloc(message->size_sigrl() * sizeof(uint8_t));
  for (size_t i = 0; i < message->size_sigrl(); i++) {
    sigrl[i] = message->sigrl(i);
  }
  memcpy(&p_ra_message2->sig_rl, &sigrl, message->size_sigrl());

  *msg2 = p_ra_message2;
}

static void assemble_attestation_message(
    const oram::AttestationMessage* message,
    ra_samp_response_header_t** pp_att_msg) {
  const size_t total_size = message->size() + message->result_size() +
                            sizeof(ra_samp_response_header_t);
  sample_ra_att_result_msg_t* p_att_result_msg = nullptr;
  ra_samp_response_header_t* p_att_result_msg_full = nullptr;

  p_att_result_msg_full = (ra_samp_response_header_t*)malloc(total_size);
  memset(p_att_result_msg_full, 0, total_size);
  p_att_result_msg_full->size = message->size();

  // Copy the data from the message and set the result.
  p_att_result_msg = reinterpret_cast<sample_ra_att_result_msg_t*>(
      p_att_result_msg_full->body);
  p_att_result_msg->platform_info_blob.sample_epid_group_status =
      message->epid_group_status();
  p_att_result_msg->platform_info_blob.sample_tcb_evaluation_status =
      message->tcb_evaluation_status();
  p_att_result_msg->platform_info_blob.pse_evaluation_status =
      message->pse_evaluation_status();

  for (size_t i = 0; i < PSVN_SIZE; i++) {
    p_att_result_msg->platform_info_blob.latest_equivalent_tcb_psvn[i] =
        message->latest_equivalent_tcb_psvn(i);
  }
  for (size_t i = 0; i < ISVSVN_SIZE; i++) {
    p_att_result_msg->platform_info_blob.latest_pse_isvsvn[i] =
        message->latest_pse_isvsvn(i);
  }
  for (size_t i = 0; i < PSDA_SVN_SIZE; i++) {
    p_att_result_msg->platform_info_blob.latest_psda_svn[i] =
        message->latest_psda_svn(i);
  }
  for (size_t i = 0; i < GID_SIZE; i++) {
    p_att_result_msg->platform_info_blob.performance_rekey_gid[i] =
        message->performance_rekey_gid(i);
  }
  for (size_t i = 0; i < SAMPLE_NISTP256_KEY_SIZE; i++) {
    p_att_result_msg->platform_info_blob.signature.x[i] =
        message->ec_sign256_x(i);
    p_att_result_msg->platform_info_blob.signature.y[i] =
        message->ec_sign256_y(i);
  }
  for (size_t i = 0; i < SAMPLE_MAC_SIZE; i++) {
    p_att_result_msg->mac[i] = message->mac_smk(i);
  }

  p_att_result_msg->secret.payload_size = message->result_size();
  for (size_t i = 0; i < 12; i++) {
    p_att_result_msg->secret.reserved[i] = message->reserved(i);
  }
  for (size_t i = 0; i < SAMPLE_SP_TAG_SIZE; i++) {
    p_att_result_msg->secret.payload_tag[i] = message->payload_tag(i);
  }
  for (size_t i = 0; i < message->result_size(); i++) {
    p_att_result_msg->secret.payload[i] =
        static_cast<uint8_t>(message->payload(i));
  }

  *pp_att_msg = p_att_result_msg_full;
}

grpc::Status SGXORAMService::init_enclave(grpc::ServerContext* server_context,
                                          const oram::InitRequest* init_request,
                                          oram::InitReply* init_reply) {
  // First check if the round number is zero.
  const uint32_t round = init_request->round();
  if (round == 0) {
    logger->info("Trying to initialize the enclave with id {}.", *global_eid);
    if (init_enclave(global_eid) != SGX_SUCCESS) {
      // A toy enclave. We only create it once.
      // If there is need to ensure that the enclave is online, please put this
      // into a loop body.
      const std::string error_message = "Enclave cannot be initialized!";
      return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
    } else {
      // Simultaneously initialize the remote attestation procedures.
      enclave_init_ra(*global_eid, &status, false, &context);

      if (status != SGX_SUCCESS) {
        // If the remote attestation cannot be initialized, we report an error
        // to the client.
        const std::string error_message = "Remote attestation failed!";
        return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
      }

      init_reply->set_success(true);
      // There is no key currently.
      return grpc::Status::OK;
    }
  } else {
    const std::string error_message = "Request has illed form!";
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  }
}

grpc::Status SGXORAMService::generate_session_key(
    grpc::ServerContext* server_context, const oram::InitRequest* init_request,
    oram::InitReply* init_reply) {
  const uint32_t round = init_request->round();
  logger->info("Begin to generate DH key pair...");

  // Start DHKE.
  if (round == 1u) {
    // Send it to the enclave.
    // Then let the enclave sample keys.
    if (ecall_begin_DHKE(*global_eid, &status) != SGX_SUCCESS) {
      const std::string error_message = "Enclave cannot create an ECC state!";
      return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
    }

    // Wait for the enclave to finish generating the public key
    // and the private key.
    uint8_t pk[sizeof(sgx_ec256_public_t)];
    if (ecall_sample_key_pair(*global_eid, &status, pk,
                              sizeof(sgx_ec256_public_t)) != SGX_SUCCESS) {
      const std::string error_message = "Enclave cannot sample the key pair!";
      return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
    }

    // After the enclave finishes generating the key pair, we can
    // send the public key to the client.
    init_reply->set_content(
        std::string((char*)&pk, sizeof(sgx_ec256_public_t)));
    return grpc::Status::OK;
  } else if (round == 2) {
    // Round = 2 denotes that the client has sent its public key to the server.
    const std::string client_pk = init_request->content();
    std::array<uint8_t, sizeof(sgx_ec256_public_t)> pk_array;
    std::copy(client_pk.begin(), client_pk.end(), pk_array.begin());
    logger->info("In server runner: {}", spdlog::to_hex(pk_array));
    // Call the enclave.
    // The enclave will generate the shared secret based on the client's public
    // key and the server's private key.
    if (ecall_compute_shared_key(*global_eid, &status,
                                 (const uint8_t*)client_pk.data(),
                                 client_pk.size()) != SGX_SUCCESS) {
      const std::string error_message =
          "Enclave cannot compute the shared key! The key is possibly "
          "corrupted!";
      return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
    }

    return grpc::Status::OK;

  } else {
    const std::string error_message = "Request has illed form!";
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  }
}

grpc::Status SGXORAMService::read_block(grpc::ServerContext* server_context,
                                        const oram::ReadRequest* read_request,
                                        oram::ReadReply* read_reply) {
  return grpc::Status::OK;
}

grpc::Status SGXORAMService::write_block(
    grpc::ServerContext* server_context,
    const oram::WriteRequest* write_request, oram::WriteReply* write_reply) {
  return grpc::Status::OK;
}

grpc::Status SGXORAMService::close_connection(
    grpc::ServerContext* server_context,
    const oram::CloseRequest* close_request, google::protobuf::Empty* empty) {
  logger->info(server_context->peer(), " - Closing connection... Goodbye!");
  server_running = false;
  return grpc::Status::OK;
}

grpc::Status SGXORAMService::remote_attestation_begin(
    grpc::ServerContext* server_context,
    const oram::InitialMessage* initial_message, oram::Message0* reply) {
  logger->info("Begin remote attestation...");
  logger->info("The server is generating the epid group id...");

  uint32_t extended_epid_group_id;
  status = sgx_get_extended_epid_group_id(&extended_epid_group_id);

  if (status != SGX_SUCCESS) {
    // There is some error in generating the epid group id.
    const std::string error_message = "Failed to generate epid group id!";
    logger->error(error_message);

    // Notify the client that the remote attestation failed.
    reply->set_epid(0ul);
    reply->set_status(-1);
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  } else {
    // If the epid group id is generated successfully, we send it to the client.
    logger->info("The server has generated the epid group id: {}",
                 extended_epid_group_id);
    reply->set_epid(extended_epid_group_id);
    return grpc::Status::OK;
  }
}

grpc::Status SGXORAMService::remote_attestation_msg0(
    grpc::ServerContext* server_context, const oram::Message0* message,
    oram::Message1* reply) {
  logger->info("Received message 0 from the client...");
  logger->info("The server is generating the message 1...");

  sgx_ra_msg1_t ra_message1;
  status = sgx_ra_get_msg1(context, *global_eid, sgx_ra_get_ga, &ra_message1);

  if (status != SGX_SUCCESS) {
    // There is some error in generating the message 1.
    const std::string error_message = "Failed to generate message 1!";
    logger->error(error_message);
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  } else {
    for (size_t i = 0; i < 32; i++) {
      reply->add_gax(ra_message1.g_a.gx[i]);
      reply->add_gay(ra_message1.g_a.gy[i]);
      reply->add_gid(ra_message1.gid[i]);
    }

    return grpc::Status::OK;
  }
}

grpc::Status SGXORAMService::remote_attestation_msg2(
    grpc::ServerContext* server_context, const oram::Message2* message,
    oram::Message3* reply) {
  logger->info("Received message 2 from the client.");
  logger->info("The server is generating the message 3...");

  const uint32_t size = message->size();
  sgx_ra_msg2_t* p_ra_message2;
  assemble_message(message, &p_ra_message2);
  logger->info("The server has assembled the message 2.");

  // Prepare the message 3.
  sgx_ra_msg3_t* p_ra_message3 = nullptr;
  uint32_t message3_size;
  uint32_t retries = 5;

  do {
    status = sgx_ra_proc_msg2(context, *global_eid, sgx_ra_proc_msg2_trusted,
                              sgx_ra_get_msg3_trusted, p_ra_message2, size,
                              &p_ra_message3, &message3_size);
  } while (SGX_ERROR_BUSY == status && retries--);

  sgx_oram::safe_free(p_ra_message2);

  if (status != SGX_SUCCESS) {
    // There is some error in generating the message 3.
    const std::string error_message = "Failed to generate message 3!";
    logger->error(error_message);
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  } else {
    reply->set_size(message3_size);

    // Copy the message 3 to the reply.
    for (size_t i = 0; i < SGX_MAC_SIZE; i++) {
      reply->add_sgx_mac(p_ra_message3->mac[i]);
    }
    for (size_t i = 0; i < SGX_ECP256_KEY_SIZE; i++) {
      reply->add_gax_msg3(p_ra_message3->g_a.gx[i]);
      reply->add_gay_msg3(p_ra_message3->g_a.gy[i]);
    }
    for (size_t i = 0; i < 256; i++) {
      reply->add_sec_property(
          p_ra_message3->ps_sec_prop.sgx_ps_sec_prop_desc[i]);
    }
    for (size_t i = 0; i < 1116; i++) {
      reply->add_quote(p_ra_message3->quote[i]);
    }

    sgx_oram::safe_free(p_ra_message3);
    logger->info("The server has successfully generated the message 3.");
    return grpc::Status::OK;
  }
}

grpc::Status SGXORAMService::remote_attestation_final(
    grpc::ServerContext* server_context,
    const oram::AttestationMessage* message, google::protobuf::Empty* empty) {
  logger->info("Received message 3 from the client.");
  logger->info("The server is generating the final attestation message...");

  ra_samp_response_header_t* p_att_result_msg_full = nullptr;
  assemble_attestation_message(message, &p_att_result_msg_full);

  // Extract the message body from the full message by skipping the header.
  sample_ra_att_result_msg_t* p_att_result_msg_body =
      (sample_ra_att_result_msg_t*)((uint8_t*)p_att_result_msg_full +
                                    sizeof(ra_samp_response_header_t));
  // Verify the attestation result message in the enclave.
  status = verify_att_result_mac(
      *global_eid, &status, context,
      (uint8_t*)&p_att_result_msg_body->platform_info_blob,
      sizeof(ias_platform_info_blob_t), (uint8_t*)&p_att_result_msg_body->mac,
      sizeof(sgx_mac_t));

  if (status != SGX_SUCCESS) {
    const std::string error_message =
        "Failed to verify the attestation result!";
    logger->error(error_message);
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  } else if (p_att_result_msg_full->status[0] != 0 ||
             p_att_result_msg_full->status[1] != 0) {
    // There is an error in the mac.
    const std::string error_message =
        "Attestation mac result message MK based CMAC failed!";
    logger->error(error_message);
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  } else {
    // Verify secret data.
    status = verify_secret_data(*global_eid, &status, context,
                                p_att_result_msg_body->secret.payload,
                                p_att_result_msg_body->secret.payload_size,
                                p_att_result_msg_body->secret.payload_tag,
                                MAX_VERIFICATION_RESULT, NULL);

    sgx_oram::safe_free(p_att_result_msg_full);

    if (status != SGX_SUCCESS) {
      const std::string error_message = "Failed to verify the secret data!";
      logger->error(error_message);
      return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
    } else {
      logger->info(
          "The server has successfully verified the secret "
          "data. Local attestation OK.");
    }
  }

  sgx_oram::safe_free(p_att_result_msg_full);
  return grpc::Status::OK;
}

grpc::Status SGXORAMService::init_oram(
    grpc::ServerContext* server_context,
    const oram::OramInitRequest* oram_init_request,
    google::protobuf::Empty* empty) {
  // The configuration of the ORAM is set by the network communication between
  // the client and the server.
  oram_config.way = oram_init_request->way();
  // Note that the total number of the block is two times of the real number of
  // block because each bucket of the ORAM contains real / fake blocks of the
  // same size.
  const uint32_t real_number = oram_init_request->number();
  oram_config.number = real_number << 1;
  oram_config.constant = oram_init_request->constant();
  oram_config.round = oram_init_request->round();
  oram_config.type = oram_init_request->type();
  oram_config.bucket_size = oram_init_request->bucket_size();
  oram_config.oram_type = oram_init_request->oram_type();

  const std::string verification_message = oram_init_request->verification();
  uint32_t* permutation = new uint32_t[real_number];

  for (size_t i = 0; i < real_number; i++) {
    permutation[i] = oram_init_request->permutation(i);
  }

  if (!check_verification_message(verification_message)) {
    const std::string error_message = "Failed to verify the message!";
    logger->error(error_message);
    server_running = false;
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  }

  // Calculate the level of the ORAM tree.
  oram_config.level =
      std::ceil(std::log(oram_config.number / oram_config.bucket_size) /
                std::log(oram_config.way)) +
      1;
  // Print the configuration.
  print_oram_config(oram_config);

  logger->info("The server has properly configured the ORAM.");

  status = ecall_init_oram_controller(
      *global_eid, &status, (uint8_t*)&oram_config, sizeof(oram_config),
      permutation, real_number * sizeof(uint32_t));

  if (status != SGX_SUCCESS) {
    const std::string error_message = "Failed to initialize the ORAM!";
    logger->error(error_message);
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  } else {
    logger->info("The server has successfully initialized the ORAM.");
  }

  // Test if data access works fine?
  sgx_oram::oram_block_t* block =
      (sgx_oram::oram_block_t*)malloc(sizeof(sgx_oram::oram_block_t));
  status = ecall_access_data(*global_eid, &status, 0, 1, (uint8_t*)block,
                             sizeof(block));
  logger->debug("ecall_data_access seems to be found.");
  return grpc::Status::OK;
}

void Server::run(const std::string& address,
                 sgx_enclave_id_t* const global_eid) {
  // Create the directory for storing slots on the disk.
  const std::string data_dir = "./data";
  if (mkdir(data_dir.c_str(), 0777) == -1) {
    if (errno != EEXIST) {
      logger->error("Failed to create the directory for storing slots!");
      exit(1);
    }
  }

  service = std::make_unique<SGXORAMService>(global_eid);
  const std::string servercert = read_keycert(key_path + "/" + "sslcred.crt");
  const std::string serverkey = read_keycert(key_path + "/" + "sslcred.key");

  grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp;
  pkcp.private_key = serverkey;
  pkcp.cert_chain = servercert;

  grpc::SslServerCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs = "";
  ssl_opts.pem_key_cert_pairs.push_back(pkcp);

  std::shared_ptr<grpc::ServerCredentials> creds;
  creds = grpc::SslServerCredentials(ssl_opts);

  grpc::ServerBuilder builder;
  builder.AddListeningPort(address, grpc::SslServerCredentials(ssl_opts));
  builder.RegisterService(service.get());

  server = (builder.BuildAndStart());
  logger->info("Server listening on {}.", address);
  server_running = true;

  // Start a monitor thread.
  std::thread monitor_thread([&, this]() {
    while (server_running)
      ;
    server->Shutdown();
  });
  monitor_thread.detach();
  server->Wait();
}

sgx_status_t SGXORAMService::init_enclave(sgx_enclave_id_t* const global_eid) {
  // Initialize the enclave by loading into the signed shared object into the
  // main memory.
  if (sgx_oram::init_enclave(global_eid) != SGX_SUCCESS) {
    logger->info("Cannot initialize the enclave!");
    return SGX_ERROR_UNEXPECTED;
  }

  return SGX_SUCCESS;
}

bool SGXORAMService::check_verification_message(const std::string& message) {
  std::array<uint8_t, 1024> message_array;
  std::copy(message.begin(), message.end(), message_array.begin());
  logger->info("The verification message is {}.",
               spdlog::to_hex(message_array.begin(),
                              message_array.begin() + message.size()));

  if (ecall_check_verification_message(*global_eid, &status,
                                       (uint8_t*)message.c_str(),
                                       message.size()) != SGX_SUCCESS) {
    logger->error("Cannot check the verification message!");
    return false;
  } else {
    logger->info("The server has successfully verified the secret data.");
    return true;
  }
}