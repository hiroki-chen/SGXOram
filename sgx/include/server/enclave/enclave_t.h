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

sgx_status_t ecall_init_oram_controller(uint8_t* config, size_t config_size, uint32_t* permutation, size_t permutation_size);
sgx_status_t ecall_access_data(int op_type, uint32_t block_address, uint8_t* data, size_t data_len);
sgx_status_t ecall_check_verification_message(uint8_t* message, size_t message_size);
sgx_status_t ecall_seal(const uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size);
sgx_status_t ecall_unseal(const sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, size_t plaintext_len);
sgx_status_t ecall_begin_DHKE(void);
sgx_status_t ecall_sample_key_pair(uint8_t* pub_key, size_t pubkey_size);
sgx_status_t ecall_compute_shared_key(const uint8_t* pub_key, size_t pubkey_size);
sgx_status_t enclave_init_ra(int b_pse, sgx_ra_context_t* p_context);
sgx_status_t enclave_ra_close(sgx_ra_context_t context);
sgx_status_t verify_att_result_mac(sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size);
sgx_status_t verify_secret_data(sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac, uint32_t max_verification_length, uint8_t* p_ret);
sgx_status_t put_secret_data(sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac);
sgx_status_t ecall_test_oram_cache(void);
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

sgx_status_t SGX_CDECL ocall_is_in_memory(int* retval, const char* slot_fingerprint);
sgx_status_t SGX_CDECL ocall_printf(const char* str);
sgx_status_t SGX_CDECL ocall_read_slot(size_t* retval, const char* slot_finderprint, uint8_t* slot, size_t slot_size);
sgx_status_t SGX_CDECL ocall_write_slot(const char* slot_finderprint, const uint8_t* slot, size_t slot_size);
sgx_status_t SGX_CDECL ocall_exception_handler(const char* err_msg);
sgx_status_t SGX_CDECL ocall_read_position(size_t* retval, const char* position_finderprint, uint8_t* position, size_t position_size);
sgx_status_t SGX_CDECL ocall_write_position(const char* position_finderprint, const uint8_t* position, size_t position_size);
sgx_status_t SGX_CDECL ocall_panic_and_flush(const char* reason);
sgx_status_t SGX_CDECL ocall_flush_log(void);
sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout);
sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self);
sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
