#include "enclave_u.h"
#include <errno.h>

typedef struct ms_obli_access_s1_t {
	uint16_t ms_op;
	uint16_t ms_flag;
	char* ms_slot;
	size_t ms_slot_len;
	char* ms_data;
	size_t ms_data_len;
	uint32_t ms_level;
	char* ms_position;
	size_t ms_position_len;
	char* ms_block;
	size_t ms_block_len;
	uint32_t ms_block_number;
} ms_obli_access_s1_t;

typedef struct ms_obli_access_S2_t {
	uint16_t ms_op;
	uint16_t ms_flag;
	char* ms_slot;
	size_t ms_slot_len;
	char* ms_data1;
	size_t ms_block_len;
	char* ms_data;
	size_t ms_data_len;
	uint32_t ms_level;
	char* ms_position;
	size_t ms_position_len;
} ms_obli_access_S2_t;

typedef struct ms_obli_access_s3_t {
	uint32_t ms_rbid;
	char* ms_data2;
	size_t ms_block_len;
	char* ms_slot;
	size_t ms_slot_len;
	uint32_t ms_level;
	char* ms_position;
	size_t ms_position_len;
} ms_obli_access_s3_t;

typedef struct ms_uniform_random_t {
	uint32_t ms_retval;
	uint32_t ms_lower;
	uint32_t ms_upper;
} ms_uniform_random_t;

typedef struct ms_test_pointer_t {
	char* ms_data;
} ms_test_pointer_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_enclave = {
	0,
	{ NULL },
};
sgx_status_t obli_access_s1(sgx_enclave_id_t eid, uint16_t op, uint16_t flag, char* slot, size_t slot_len, char* data, uint32_t level, char* position, size_t position_len, char* block, size_t block_len, uint32_t block_number)
{
	sgx_status_t status;
	ms_obli_access_s1_t ms;
	ms.ms_op = op;
	ms.ms_flag = flag;
	ms.ms_slot = slot;
	ms.ms_slot_len = slot_len;
	ms.ms_data = data;
	ms.ms_data_len = data ? strlen(data) + 1 : 0;
	ms.ms_level = level;
	ms.ms_position = position;
	ms.ms_position_len = position_len;
	ms.ms_block = block;
	ms.ms_block_len = block_len;
	ms.ms_block_number = block_number;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t obli_access_S2(sgx_enclave_id_t eid, uint16_t op, uint16_t flag, char* slot, size_t slot_len, char* data1, size_t block_len, char* data, uint32_t level, char* position, size_t position_len)
{
	sgx_status_t status;
	ms_obli_access_S2_t ms;
	ms.ms_op = op;
	ms.ms_flag = flag;
	ms.ms_slot = slot;
	ms.ms_slot_len = slot_len;
	ms.ms_data1 = data1;
	ms.ms_block_len = block_len;
	ms.ms_data = data;
	ms.ms_data_len = data ? strlen(data) + 1 : 0;
	ms.ms_level = level;
	ms.ms_position = position;
	ms.ms_position_len = position_len;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t obli_access_s3(sgx_enclave_id_t eid, uint32_t rbid, char* data2, size_t block_len, char* slot, size_t slot_len, uint32_t level, char* position, size_t position_len)
{
	sgx_status_t status;
	ms_obli_access_s3_t ms;
	ms.ms_rbid = rbid;
	ms.ms_data2 = data2;
	ms.ms_block_len = block_len;
	ms.ms_slot = slot;
	ms.ms_slot_len = slot_len;
	ms.ms_level = level;
	ms.ms_position = position;
	ms.ms_position_len = position_len;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t uniform_random(sgx_enclave_id_t eid, uint32_t* retval, uint32_t lower, uint32_t upper)
{
	sgx_status_t status;
	ms_uniform_random_t ms;
	ms.ms_lower = lower;
	ms.ms_upper = upper;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t test_pointer(sgx_enclave_id_t eid, char* data)
{
	sgx_status_t status;
	ms_test_pointer_t ms;
	ms.ms_data = data;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
	return status;
}

