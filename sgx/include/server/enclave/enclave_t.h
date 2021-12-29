#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_key_exchange.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_init_oram_controller(void);
sgx_status_t ecall_seal(const uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size);
sgx_status_t ecall_unseal(const sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, size_t plaintext_len);
sgx_status_t ecall_begin_DHKE(void);
sgx_status_t ecall_sample_key_pair(uint8_t* pub_key, size_t pubkey_size);
sgx_status_t ecall_compute_shared_key(const uint8_t* pub_key, size_t pubkey_size);
sgx_status_t enclave_init_ra(int b_pse, sgx_ra_context_t* p_context);
sgx_status_t enclave_ra_close(sgx_ra_context_t context);
sgx_status_t verify_att_result_mac(sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size);
sgx_status_t put_secret_data(sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac);
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

sgx_status_t SGX_CDECL ocall_printf(const char* str);
sgx_status_t SGX_CDECL ocall_get_slot(const char* slot_fingerprint);
sgx_status_t SGX_CDECL ocall_write_slot(const char* slot_finger_print, const uint8_t* data, size_t data_len);
sgx_status_t SGX_CDECL ocall_exception_handler(const char* err_msg);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
