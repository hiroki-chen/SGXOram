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


sgx_status_t obli_access_s1(sgx_enclave_id_t eid, uint16_t op, uint16_t flag, char* slot, size_t slot_len, char* data, uint32_t level, char* position, size_t position_len, char* block, size_t block_len, uint32_t block_number);
sgx_status_t obli_access_S2(sgx_enclave_id_t eid, uint16_t op, uint16_t flag, char* slot, size_t slot_len, char* data1, size_t block_len, char* data, uint32_t level, char* position, size_t position_len);
sgx_status_t obli_access_s3(sgx_enclave_id_t eid, uint32_t rbid, char* data2, size_t block_len, char* slot, size_t slot_len, uint32_t level, char* position, size_t position_len);
sgx_status_t uniform_random(sgx_enclave_id_t eid, uint32_t* retval, uint32_t lower, uint32_t upper);
sgx_status_t test_pointer(sgx_enclave_id_t eid, char* data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
