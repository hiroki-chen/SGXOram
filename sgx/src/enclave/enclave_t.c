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

static sgx_status_t SGX_CDECL sgx_obli_access_s1(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_obli_access_s1_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_obli_access_s1_t* ms = SGX_CAST(ms_obli_access_s1_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_slot = ms->ms_slot;
	size_t _tmp_slot_len = ms->ms_slot_len;
	size_t _len_slot = _tmp_slot_len;
	char* _in_slot = NULL;
	char* _tmp_data = ms->ms_data;
	size_t _len_data = ms->ms_data_len ;
	char* _in_data = NULL;
	char* _tmp_position = ms->ms_position;
	size_t _tmp_position_len = ms->ms_position_len;
	size_t _len_position = _tmp_position_len;
	char* _in_position = NULL;
	char* _tmp_block = ms->ms_block;
	size_t _tmp_block_len = ms->ms_block_len;
	size_t _len_block = _tmp_block_len;
	char* _in_block = NULL;

	CHECK_UNIQUE_POINTER(_tmp_slot, _len_slot);
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_position, _len_position);
	CHECK_UNIQUE_POINTER(_tmp_block, _len_block);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_slot != NULL && _len_slot != 0) {
		if ( _len_slot % sizeof(*_tmp_slot) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_slot = (char*)malloc(_len_slot);
		if (_in_slot == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_slot, _len_slot, _tmp_slot, _len_slot)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_data != NULL && _len_data != 0) {
		_in_data = (char*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_data[_len_data - 1] = '\0';
		if (_len_data != strlen(_in_data) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_position != NULL && _len_position != 0) {
		if ( _len_position % sizeof(*_tmp_position) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_position = (char*)malloc(_len_position);
		if (_in_position == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_position, _len_position, _tmp_position, _len_position)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_block != NULL && _len_block != 0) {
		if ( _len_block % sizeof(*_tmp_block) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_block = (char*)malloc(_len_block)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_block, 0, _len_block);
	}

	obli_access_s1(ms->ms_op, ms->ms_flag, _in_slot, _tmp_slot_len, _in_data, ms->ms_level, _in_position, _tmp_position_len, _in_block, _tmp_block_len, ms->ms_block_number);
	if (_in_slot) {
		if (memcpy_s(_tmp_slot, _len_slot, _in_slot, _len_slot)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_data)
	{
		_in_data[_len_data - 1] = '\0';
		_len_data = strlen(_in_data) + 1;
		if (memcpy_s((void*)_tmp_data, _len_data, _in_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_position) {
		if (memcpy_s(_tmp_position, _len_position, _in_position, _len_position)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_block) {
		if (memcpy_s(_tmp_block, _len_block, _in_block, _len_block)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_slot) free(_in_slot);
	if (_in_data) free(_in_data);
	if (_in_position) free(_in_position);
	if (_in_block) free(_in_block);
	return status;
}

static sgx_status_t SGX_CDECL sgx_obli_access_S2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_obli_access_S2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_obli_access_S2_t* ms = SGX_CAST(ms_obli_access_S2_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_slot = ms->ms_slot;
	size_t _tmp_slot_len = ms->ms_slot_len;
	size_t _len_slot = _tmp_slot_len;
	char* _in_slot = NULL;
	char* _tmp_data1 = ms->ms_data1;
	size_t _tmp_block_len = ms->ms_block_len;
	size_t _len_data1 = _tmp_block_len;
	char* _in_data1 = NULL;
	char* _tmp_data = ms->ms_data;
	size_t _len_data = ms->ms_data_len ;
	char* _in_data = NULL;
	char* _tmp_position = ms->ms_position;
	size_t _tmp_position_len = ms->ms_position_len;
	size_t _len_position = _tmp_position_len;
	char* _in_position = NULL;

	CHECK_UNIQUE_POINTER(_tmp_slot, _len_slot);
	CHECK_UNIQUE_POINTER(_tmp_data1, _len_data1);
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_position, _len_position);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_slot != NULL && _len_slot != 0) {
		if ( _len_slot % sizeof(*_tmp_slot) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_slot = (char*)malloc(_len_slot);
		if (_in_slot == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_slot, _len_slot, _tmp_slot, _len_slot)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_data1 != NULL && _len_data1 != 0) {
		if ( _len_data1 % sizeof(*_tmp_data1) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data1 = (char*)malloc(_len_data1);
		if (_in_data1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data1, _len_data1, _tmp_data1, _len_data1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_data != NULL && _len_data != 0) {
		_in_data = (char*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_data[_len_data - 1] = '\0';
		if (_len_data != strlen(_in_data) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_position != NULL && _len_position != 0) {
		if ( _len_position % sizeof(*_tmp_position) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_position = (char*)malloc(_len_position);
		if (_in_position == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_position, _len_position, _tmp_position, _len_position)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	obli_access_S2(ms->ms_op, ms->ms_flag, _in_slot, _tmp_slot_len, _in_data1, _tmp_block_len, _in_data, ms->ms_level, _in_position, _tmp_position_len);
	if (_in_slot) {
		if (memcpy_s(_tmp_slot, _len_slot, _in_slot, _len_slot)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_data1) {
		if (memcpy_s(_tmp_data1, _len_data1, _in_data1, _len_data1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_data)
	{
		_in_data[_len_data - 1] = '\0';
		_len_data = strlen(_in_data) + 1;
		if (memcpy_s((void*)_tmp_data, _len_data, _in_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_position) {
		if (memcpy_s(_tmp_position, _len_position, _in_position, _len_position)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_slot) free(_in_slot);
	if (_in_data1) free(_in_data1);
	if (_in_data) free(_in_data);
	if (_in_position) free(_in_position);
	return status;
}

static sgx_status_t SGX_CDECL sgx_obli_access_s3(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_obli_access_s3_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_obli_access_s3_t* ms = SGX_CAST(ms_obli_access_s3_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_data2 = ms->ms_data2;
	size_t _tmp_block_len = ms->ms_block_len;
	size_t _len_data2 = _tmp_block_len;
	char* _in_data2 = NULL;
	char* _tmp_slot = ms->ms_slot;
	size_t _tmp_slot_len = ms->ms_slot_len;
	size_t _len_slot = _tmp_slot_len;
	char* _in_slot = NULL;
	char* _tmp_position = ms->ms_position;
	size_t _tmp_position_len = ms->ms_position_len;
	size_t _len_position = _tmp_position_len;
	char* _in_position = NULL;

	CHECK_UNIQUE_POINTER(_tmp_data2, _len_data2);
	CHECK_UNIQUE_POINTER(_tmp_slot, _len_slot);
	CHECK_UNIQUE_POINTER(_tmp_position, _len_position);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_data2 != NULL && _len_data2 != 0) {
		if ( _len_data2 % sizeof(*_tmp_data2) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data2 = (char*)malloc(_len_data2);
		if (_in_data2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data2, _len_data2, _tmp_data2, _len_data2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_slot != NULL && _len_slot != 0) {
		if ( _len_slot % sizeof(*_tmp_slot) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_slot = (char*)malloc(_len_slot);
		if (_in_slot == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_slot, _len_slot, _tmp_slot, _len_slot)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_position != NULL && _len_position != 0) {
		if ( _len_position % sizeof(*_tmp_position) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_position = (char*)malloc(_len_position);
		if (_in_position == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_position, _len_position, _tmp_position, _len_position)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	obli_access_s3(ms->ms_rbid, _in_data2, _tmp_block_len, _in_slot, _tmp_slot_len, ms->ms_level, _in_position, _tmp_position_len);
	if (_in_data2) {
		if (memcpy_s(_tmp_data2, _len_data2, _in_data2, _len_data2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_slot) {
		if (memcpy_s(_tmp_slot, _len_slot, _in_slot, _len_slot)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_position) {
		if (memcpy_s(_tmp_position, _len_position, _in_position, _len_position)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_data2) free(_in_data2);
	if (_in_slot) free(_in_slot);
	if (_in_position) free(_in_position);
	return status;
}

static sgx_status_t SGX_CDECL sgx_uniform_random(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_uniform_random_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_uniform_random_t* ms = SGX_CAST(ms_uniform_random_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = uniform_random(ms->ms_lower, ms->ms_upper);


	return status;
}

static sgx_status_t SGX_CDECL sgx_test_pointer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_test_pointer_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_test_pointer_t* ms = SGX_CAST(ms_test_pointer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_data = ms->ms_data;
	size_t _len_data = sizeof(char);
	char* _in_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (char*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	test_pointer(_in_data);
	if (_in_data) {
		if (memcpy_s(_tmp_data, _len_data, _in_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_data) free(_in_data);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_obli_access_s1, 0, 0},
		{(void*)(uintptr_t)sgx_obli_access_S2, 0, 0},
		{(void*)(uintptr_t)sgx_obli_access_s3, 0, 0},
		{(void*)(uintptr_t)sgx_uniform_random, 0, 0},
		{(void*)(uintptr_t)sgx_test_pointer, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


