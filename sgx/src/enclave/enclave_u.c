#include "enclave_u.h"
#include <errno.h>

static sgx_status_t SGX_CDECL enclave_ocall_print_something(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_print_something();
	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_enclave = {
	1,
	{
		(void*)enclave_ocall_print_something,
	}
};
sgx_status_t print_something(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, NULL);
	return status;
}

