#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_init_oram_controller(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_oram_controller_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_init_oram_controller_t* ms = SGX_CAST(ms_ecall_init_oram_controller_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_init_oram_controller();


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_ecall_init_oram_controller, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][1];
} g_dyn_entry_table = {
	3,
	{
		{0, },
		{0, },
		{0, },
	}
};


sgx_status_t SGX_CDECL ocall_printf(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_printf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_printf_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_printf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_printf_t));
	ocalloc_size -= sizeof(ms_ocall_printf_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_slot(const char* slot_fingerprint)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_slot_fingerprint = slot_fingerprint ? strlen(slot_fingerprint) + 1 : 0;

	ms_ocall_get_slot_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_slot_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(slot_fingerprint, _len_slot_fingerprint);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (slot_fingerprint != NULL) ? _len_slot_fingerprint : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_slot_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_slot_t));
	ocalloc_size -= sizeof(ms_ocall_get_slot_t);

	if (slot_fingerprint != NULL) {
		ms->ms_slot_fingerprint = (const char*)__tmp;
		if (_len_slot_fingerprint % sizeof(*slot_fingerprint) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, slot_fingerprint, _len_slot_fingerprint)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_slot_fingerprint);
		ocalloc_size -= _len_slot_fingerprint;
	} else {
		ms->ms_slot_fingerprint = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_exception_handler(const char* err_msg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_err_msg = err_msg ? strlen(err_msg) + 1 : 0;

	ms_ocall_exception_handler_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_exception_handler_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(err_msg, _len_err_msg);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (err_msg != NULL) ? _len_err_msg : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_exception_handler_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_exception_handler_t));
	ocalloc_size -= sizeof(ms_ocall_exception_handler_t);

	if (err_msg != NULL) {
		ms->ms_err_msg = (const char*)__tmp;
		if (_len_err_msg % sizeof(*err_msg) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, err_msg, _len_err_msg)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_err_msg);
		ocalloc_size -= _len_err_msg;
	} else {
		ms->ms_err_msg = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

