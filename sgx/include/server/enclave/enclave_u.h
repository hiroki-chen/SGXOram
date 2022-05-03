#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_key_exchange.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_IS_IN_MEMORY_DEFINED__
#define OCALL_IS_IN_MEMORY_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_is_in_memory, (const char* slot_fingerprint));
#endif
#ifndef OCALL_PRINTF_DEFINED__
#define OCALL_PRINTF_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_printf, (const char* str));
#endif
#ifndef OCALL_READ_SLOT_DEFINED__
#define OCALL_READ_SLOT_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_slot, (const char* slot_finderprint, uint8_t* slot, size_t slot_size));
#endif
#ifndef OCALL_WRITE_SLOT_DEFINED__
#define OCALL_WRITE_SLOT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_slot, (const char* slot_finderprint, const uint8_t* slot, size_t slot_size));
#endif
#ifndef OCALL_EXCEPTION_HANDLER_DEFINED__
#define OCALL_EXCEPTION_HANDLER_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_exception_handler, (const char* err_msg));
#endif
#ifndef OCALL_READ_POSITION_DEFINED__
#define OCALL_READ_POSITION_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_position, (const char* position_finderprint, uint8_t* position, size_t position_size));
#endif
#ifndef OCALL_WRITE_POSITION_DEFINED__
#define OCALL_WRITE_POSITION_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_position, (const char* position_finderprint, const uint8_t* position, size_t position_size));
#endif
#ifndef OCALL_PANIC_AND_FLUSH_DEFINED__
#define OCALL_PANIC_AND_FLUSH_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_panic_and_flush, (const char* reason));
#endif
#ifndef OCALL_FLUSH_LOG_DEFINED__
#define OCALL_FLUSH_LOG_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_flush_log, (void));
#endif
#ifndef PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
#define PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wait_timeout_ocall, (unsigned long long waiter, unsigned long long timeout));
#endif
#ifndef PTHREAD_CREATE_OCALL_DEFINED__
#define PTHREAD_CREATE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_create_ocall, (unsigned long long self));
#endif
#ifndef PTHREAD_WAKEUP_OCALL_DEFINED__
#define PTHREAD_WAKEUP_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wakeup_ocall, (unsigned long long waiter));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t ecall_init_oram_controller(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* config, size_t config_size, uint32_t* permutation, size_t permutation_size);
sgx_status_t ecall_access_data(sgx_enclave_id_t eid, sgx_status_t* retval, int op_type, uint32_t block_address, uint8_t* data, size_t data_len);
sgx_status_t ecall_check_verification_message(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* message, size_t message_size);
sgx_status_t ecall_seal(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size);
sgx_status_t ecall_unseal(sgx_enclave_id_t eid, sgx_status_t* retval, const sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, size_t plaintext_len);
sgx_status_t ecall_begin_DHKE(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t ecall_sample_key_pair(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* pub_key, size_t pubkey_size);
sgx_status_t ecall_compute_shared_key(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* pub_key, size_t pubkey_size);
sgx_status_t enclave_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context);
sgx_status_t enclave_ra_close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context);
sgx_status_t verify_att_result_mac(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size);
sgx_status_t verify_secret_data(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac, uint32_t max_verification_length, uint8_t* p_ret);
sgx_status_t put_secret_data(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac);
sgx_status_t ecall_test_oram_cache(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
