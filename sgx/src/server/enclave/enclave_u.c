#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_init_oram_controller_t {
	sgx_status_t ms_retval;
	uint8_t* ms_oram_config;
	size_t ms_oram_config_size;
} ms_ecall_init_oram_controller_t;

typedef struct ms_ecall_access_data_t {
	sgx_status_t ms_retval;
	int ms_op_type;
	uint8_t* ms_data;
	size_t ms_data_len;
} ms_ecall_access_data_t;

typedef struct ms_ecall_check_verification_message_t {
	sgx_status_t ms_retval;
	uint8_t* ms_message;
	size_t ms_message_size;
} ms_ecall_check_verification_message_t;

typedef struct ms_ecall_seal_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_plaintext;
	size_t ms_plaintext_len;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_ecall_seal_t;

typedef struct ms_ecall_unseal_t {
	sgx_status_t ms_retval;
	const sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
	uint8_t* ms_plaintext;
	size_t ms_plaintext_len;
} ms_ecall_unseal_t;

typedef struct ms_ecall_init_crypto_manager_t {
	sgx_status_t ms_retval;
} ms_ecall_init_crypto_manager_t;

typedef struct ms_ecall_begin_DHKE_t {
	sgx_status_t ms_retval;
} ms_ecall_begin_DHKE_t;

typedef struct ms_ecall_sample_key_pair_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pub_key;
	size_t ms_pubkey_size;
} ms_ecall_sample_key_pair_t;

typedef struct ms_ecall_compute_shared_key_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_pub_key;
	size_t ms_pubkey_size;
} ms_ecall_compute_shared_key_t;

typedef struct ms_enclave_init_ra_t {
	sgx_status_t ms_retval;
	int ms_b_pse;
	sgx_ra_context_t* ms_p_context;
} ms_enclave_init_ra_t;

typedef struct ms_enclave_ra_close_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
} ms_enclave_ra_close_t;

typedef struct ms_verify_att_result_mac_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_message;
	size_t ms_message_size;
	uint8_t* ms_mac;
	size_t ms_mac_size;
} ms_verify_att_result_mac_t;

typedef struct ms_verify_secret_data_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_p_secret;
	uint32_t ms_secret_size;
	uint8_t* ms_gcm_mac;
	uint32_t ms_max_verification_length;
	uint8_t* ms_p_ret;
} ms_verify_secret_data_t;

typedef struct ms_put_secret_data_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_p_secret;
	uint32_t ms_secret_size;
	uint8_t* ms_gcm_mac;
} ms_put_secret_data_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const sgx_ra_msg2_t* ms_p_msg2;
	const sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_ocall_printf_t {
	const char* ms_str;
} ms_ocall_printf_t;

typedef struct ms_ocall_read_slot_t {
	size_t ms_retval;
	const char* ms_slot_finderprint;
	uint8_t* ms_slot;
	size_t ms_slot_size;
} ms_ocall_read_slot_t;

typedef struct ms_ocall_write_slot_t {
	const char* ms_slot_finderprint;
	const uint8_t* ms_slot;
	size_t ms_slot_size;
} ms_ocall_write_slot_t;

typedef struct ms_ocall_exception_handler_t {
	const char* ms_err_msg;
} ms_ocall_exception_handler_t;

typedef struct ms_ocall_read_position_t {
	size_t ms_retval;
	const char* ms_position_finderprint;
	uint8_t* ms_position;
	size_t ms_position_size;
} ms_ocall_read_position_t;

typedef struct ms_ocall_write_position_t {
	const char* ms_position_finderprint;
	const uint8_t* ms_position;
	size_t ms_position_size;
} ms_ocall_write_position_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL enclave_ocall_printf(void* pms)
{
	ms_ocall_printf_t* ms = SGX_CAST(ms_ocall_printf_t*, pms);
	ocall_printf(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_read_slot(void* pms)
{
	ms_ocall_read_slot_t* ms = SGX_CAST(ms_ocall_read_slot_t*, pms);
	ms->ms_retval = ocall_read_slot(ms->ms_slot_finderprint, ms->ms_slot, ms->ms_slot_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_write_slot(void* pms)
{
	ms_ocall_write_slot_t* ms = SGX_CAST(ms_ocall_write_slot_t*, pms);
	ocall_write_slot(ms->ms_slot_finderprint, ms->ms_slot, ms->ms_slot_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_exception_handler(void* pms)
{
	ms_ocall_exception_handler_t* ms = SGX_CAST(ms_ocall_exception_handler_t*, pms);
	ocall_exception_handler(ms->ms_err_msg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_read_position(void* pms)
{
	ms_ocall_read_position_t* ms = SGX_CAST(ms_ocall_read_position_t*, pms);
	ms->ms_retval = ocall_read_position(ms->ms_position_finderprint, ms->ms_position, ms->ms_position_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_write_position(void* pms)
{
	ms_ocall_write_position_t* ms = SGX_CAST(ms_ocall_write_position_t*, pms);
	ocall_write_position(ms->ms_position_finderprint, ms->ms_position, ms->ms_position_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[14];
} ocall_table_enclave = {
	14,
	{
		(void*)enclave_ocall_printf,
		(void*)enclave_ocall_read_slot,
		(void*)enclave_ocall_write_slot,
		(void*)enclave_ocall_exception_handler,
		(void*)enclave_ocall_read_position,
		(void*)enclave_ocall_write_position,
		(void*)enclave_pthread_wait_timeout_ocall,
		(void*)enclave_pthread_create_ocall,
		(void*)enclave_pthread_wakeup_ocall,
		(void*)enclave_sgx_oc_cpuidex,
		(void*)enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_init_oram_controller(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* oram_config, size_t oram_config_size)
{
	sgx_status_t status;
	ms_ecall_init_oram_controller_t ms;
	ms.ms_oram_config = oram_config;
	ms.ms_oram_config_size = oram_config_size;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_access_data(sgx_enclave_id_t eid, sgx_status_t* retval, int op_type, uint8_t* data, size_t data_len)
{
	sgx_status_t status;
	ms_ecall_access_data_t ms;
	ms.ms_op_type = op_type;
	ms.ms_data = data;
	ms.ms_data_len = data_len;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_check_verification_message(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* message, size_t message_size)
{
	sgx_status_t status;
	ms_ecall_check_verification_message_t ms;
	ms.ms_message = message;
	ms.ms_message_size = message_size;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_seal(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status;
	ms_ecall_seal_t ms;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_len = plaintext_len;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_unseal(sgx_enclave_id_t eid, sgx_status_t* retval, const sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, size_t plaintext_len)
{
	sgx_status_t status;
	ms_ecall_unseal_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_len = plaintext_len;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_init_crypto_manager(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_ecall_init_crypto_manager_t ms;
	status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_begin_DHKE(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_ecall_begin_DHKE_t ms;
	status = sgx_ecall(eid, 6, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sample_key_pair(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* pub_key, size_t pubkey_size)
{
	sgx_status_t status;
	ms_ecall_sample_key_pair_t ms;
	ms.ms_pub_key = pub_key;
	ms.ms_pubkey_size = pubkey_size;
	status = sgx_ecall(eid, 7, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_compute_shared_key(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* pub_key, size_t pubkey_size)
{
	sgx_status_t status;
	ms_ecall_compute_shared_key_t ms;
	ms.ms_pub_key = pub_key;
	ms.ms_pubkey_size = pubkey_size;
	status = sgx_ecall(eid, 8, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context)
{
	sgx_status_t status;
	ms_enclave_init_ra_t ms;
	ms.ms_b_pse = b_pse;
	ms.ms_p_context = p_context;
	status = sgx_ecall(eid, 9, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_ra_close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context)
{
	sgx_status_t status;
	ms_enclave_ra_close_t ms;
	ms.ms_context = context;
	status = sgx_ecall(eid, 10, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t verify_att_result_mac(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size)
{
	sgx_status_t status;
	ms_verify_att_result_mac_t ms;
	ms.ms_context = context;
	ms.ms_message = message;
	ms.ms_message_size = message_size;
	ms.ms_mac = mac;
	ms.ms_mac_size = mac_size;
	status = sgx_ecall(eid, 11, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t verify_secret_data(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac, uint32_t max_verification_length, uint8_t* p_ret)
{
	sgx_status_t status;
	ms_verify_secret_data_t ms;
	ms.ms_context = context;
	ms.ms_p_secret = p_secret;
	ms.ms_secret_size = secret_size;
	ms.ms_gcm_mac = gcm_mac;
	ms.ms_max_verification_length = max_verification_length;
	ms.ms_p_ret = p_ret;
	status = sgx_ecall(eid, 12, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t put_secret_data(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac)
{
	sgx_status_t status;
	ms_put_secret_data_t ms;
	ms.ms_context = context;
	ms.ms_p_secret = p_secret;
	ms.ms_secret_size = secret_size;
	ms.ms_gcm_mac = gcm_mac;
	status = sgx_ecall(eid, 13, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 14, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = p_msg2;
	ms.ms_p_qe_target = p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 15, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 16, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

