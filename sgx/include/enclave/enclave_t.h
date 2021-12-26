#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_init_oram_controller(void);

sgx_status_t SGX_CDECL ocall_printf(const char* str);
sgx_status_t SGX_CDECL ocall_get_slot(const char* slot_fingerprint);
sgx_status_t SGX_CDECL ocall_exception_handler(const char* err_msg);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
