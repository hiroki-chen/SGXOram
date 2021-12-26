#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_init_oram_controller_t {
	int ms_retval;
} ms_ecall_init_oram_controller_t;

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

typedef struct ms_ocall_printf_t {
	const char* ms_str;
} ms_ocall_printf_t;

typedef struct ms_ocall_get_slot_t {
	const char* ms_slot_fingerprint;
} ms_ocall_get_slot_t;

typedef struct ms_ocall_exception_handler_t {
	const char* ms_err_msg;
} ms_ocall_exception_handler_t;

static sgx_status_t SGX_CDECL enclave_ocall_printf(void* pms)
{
	ms_ocall_printf_t* ms = SGX_CAST(ms_ocall_printf_t*, pms);
	ocall_printf(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_get_slot(void* pms)
{
	ms_ocall_get_slot_t* ms = SGX_CAST(ms_ocall_get_slot_t*, pms);
	ocall_get_slot(ms->ms_slot_fingerprint);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_exception_handler(void* pms)
{
	ms_ocall_exception_handler_t* ms = SGX_CAST(ms_ocall_exception_handler_t*, pms);
	ocall_exception_handler(ms->ms_err_msg);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[3];
} ocall_table_enclave = {
	3,
	{
		(void*)enclave_ocall_printf,
		(void*)enclave_ocall_get_slot,
		(void*)enclave_ocall_exception_handler,
	}
};
sgx_status_t ecall_init_oram_controller(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_init_oram_controller_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
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
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
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
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

