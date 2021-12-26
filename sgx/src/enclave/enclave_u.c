#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_init_oram_controller_t {
	int ms_retval;
} ms_ecall_init_oram_controller_t;

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

