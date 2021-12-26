#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_tseal.h"

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
sgx_status_t ecall_seal(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size);
sgx_status_t ecall_unseal(sgx_enclave_id_t eid, sgx_status_t* retval, const sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, size_t plaintext_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
