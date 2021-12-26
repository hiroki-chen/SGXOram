#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINTF_DEFINED__
#define OCALL_PRINTF_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_printf, (const char* str));
#endif
#ifndef OCALL_GET_SLOT_DEFINED__
#define OCALL_GET_SLOT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_slot, (const char* slot_fingerprint));
#endif
#ifndef OCALL_EXCEPTION_HANDLER_DEFINED__
#define OCALL_EXCEPTION_HANDLER_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_exception_handler, (const char* err_msg));
#endif

sgx_status_t ecall_init_oram_controller(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
