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

void obli_access_s1(uint16_t op, uint16_t flag, char* slot, size_t slot_len, char* data, uint32_t level, char* position, size_t position_len, char* block, size_t block_len, uint32_t block_number);
void obli_access_S2(uint16_t op, uint16_t flag, char* slot, size_t slot_len, char* data1, size_t block_len, char* data, uint32_t level, char* position, size_t position_len);
void obli_access_s3(uint32_t rbid, char* data2, size_t block_len, char* slot, size_t slot_len, uint32_t level, char* position, size_t position_len);
uint32_t uniform_random(uint32_t lower, uint32_t upper);
void test_pointer(char* data);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
