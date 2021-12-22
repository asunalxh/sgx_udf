#include "Enclave_t.h"

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


typedef struct ms_ecall_add_t {
	char* ms_id_data;
	size_t ms_id_data_len;
	char* ms_valuesPointer;
	size_t ms_valuesPointer_len;
	char* ms_u_arr;
	char* ms_v_arr;
	size_t ms_out_size;
} ms_ecall_add_t;

typedef struct ms_ecall_del_t {
	char* ms_id_str;
	size_t ms_id_len;
} ms_ecall_del_t;

typedef struct ms_ecall_search_t {
	char* ms_id_str;
	size_t ms_id_str_len;
} ms_ecall_search_t;

typedef struct ms_get_sealed_data_size_t {
	uint32_t ms_retval;
	const char* ms_encrypt_data;
	size_t ms_encrypt_data_len;
} ms_get_sealed_data_size_t;

typedef struct ms_seal_data_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_blob;
	uint32_t ms_data_size;
	const char* ms_encrypt_data;
	size_t ms_encrypt_data_len;
} ms_seal_data_t;

typedef struct ms_get_sealed_state_size_t {
	uint32_t ms_retval;
} ms_get_sealed_state_size_t;

typedef struct ms_get_sealed_state_t {
	sgx_status_t ms_retval;
	uint8_t* ms_out;
	uint32_t ms_size;
} ms_get_sealed_state_t;

typedef struct ms_ecall_unseal_state_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_sealed_blob;
	size_t ms_data_size;
} ms_ecall_unseal_state_t;

typedef struct ms_unseal_data_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_sealed_blob;
	size_t ms_data_size;
	char* ms_out;
} ms_unseal_data_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_search_t {
	void* ms_w_u_arr;
	void* ms_w_id_arr;
	size_t ms_count;
	size_t ms_size;
} ms_ocall_search_t;

static sgx_status_t SGX_CDECL sgx_ecall_init(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_init();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_add(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_add_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_add_t* ms = SGX_CAST(ms_ecall_add_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_id_data = ms->ms_id_data;
	size_t _len_id_data = ms->ms_id_data_len ;
	char* _in_id_data = NULL;
	char* _tmp_valuesPointer = ms->ms_valuesPointer;
	size_t _len_valuesPointer = ms->ms_valuesPointer_len ;
	char* _in_valuesPointer = NULL;
	char* _tmp_u_arr = ms->ms_u_arr;
	size_t _tmp_out_size = ms->ms_out_size;
	size_t _len_u_arr = _tmp_out_size;
	char* _in_u_arr = NULL;
	char* _tmp_v_arr = ms->ms_v_arr;
	size_t _len_v_arr = _tmp_out_size;
	char* _in_v_arr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_id_data, _len_id_data);
	CHECK_UNIQUE_POINTER(_tmp_valuesPointer, _len_valuesPointer);
	CHECK_UNIQUE_POINTER(_tmp_u_arr, _len_u_arr);
	CHECK_UNIQUE_POINTER(_tmp_v_arr, _len_v_arr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_id_data != NULL && _len_id_data != 0) {
		_in_id_data = (char*)malloc(_len_id_data);
		if (_in_id_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_id_data, _len_id_data, _tmp_id_data, _len_id_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_id_data[_len_id_data - 1] = '\0';
		if (_len_id_data != strlen(_in_id_data) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_valuesPointer != NULL && _len_valuesPointer != 0) {
		_in_valuesPointer = (char*)malloc(_len_valuesPointer);
		if (_in_valuesPointer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_valuesPointer, _len_valuesPointer, _tmp_valuesPointer, _len_valuesPointer)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_valuesPointer[_len_valuesPointer - 1] = '\0';
		if (_len_valuesPointer != strlen(_in_valuesPointer) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_u_arr != NULL && _len_u_arr != 0) {
		if ( _len_u_arr % sizeof(*_tmp_u_arr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_u_arr = (char*)malloc(_len_u_arr)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_u_arr, 0, _len_u_arr);
	}
	if (_tmp_v_arr != NULL && _len_v_arr != 0) {
		if ( _len_v_arr % sizeof(*_tmp_v_arr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_v_arr = (char*)malloc(_len_v_arr)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_v_arr, 0, _len_v_arr);
	}

	ecall_add(_in_id_data, _in_valuesPointer, _in_u_arr, _in_v_arr, _tmp_out_size);
	if (_in_u_arr) {
		if (memcpy_s(_tmp_u_arr, _len_u_arr, _in_u_arr, _len_u_arr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_v_arr) {
		if (memcpy_s(_tmp_v_arr, _len_v_arr, _in_v_arr, _len_v_arr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_id_data) free(_in_id_data);
	if (_in_valuesPointer) free(_in_valuesPointer);
	if (_in_u_arr) free(_in_u_arr);
	if (_in_v_arr) free(_in_v_arr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_del(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_del_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_del_t* ms = SGX_CAST(ms_ecall_del_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_id_str = ms->ms_id_str;
	size_t _tmp_id_len = ms->ms_id_len;
	size_t _len_id_str = _tmp_id_len;
	char* _in_id_str = NULL;

	CHECK_UNIQUE_POINTER(_tmp_id_str, _len_id_str);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_id_str != NULL && _len_id_str != 0) {
		if ( _len_id_str % sizeof(*_tmp_id_str) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_id_str = (char*)malloc(_len_id_str);
		if (_in_id_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_id_str, _len_id_str, _tmp_id_str, _len_id_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_del(_in_id_str, _tmp_id_len);

err:
	if (_in_id_str) free(_in_id_str);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_search(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_search_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_search_t* ms = SGX_CAST(ms_ecall_search_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_id_str = ms->ms_id_str;
	size_t _len_id_str = ms->ms_id_str_len ;
	char* _in_id_str = NULL;

	CHECK_UNIQUE_POINTER(_tmp_id_str, _len_id_str);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_id_str != NULL && _len_id_str != 0) {
		_in_id_str = (char*)malloc(_len_id_str);
		if (_in_id_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_id_str, _len_id_str, _tmp_id_str, _len_id_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_id_str[_len_id_str - 1] = '\0';
		if (_len_id_str != strlen(_in_id_str) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ecall_search(_in_id_str);

err:
	if (_in_id_str) free(_in_id_str);
	return status;
}

static sgx_status_t SGX_CDECL sgx_get_sealed_data_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_sealed_data_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_sealed_data_size_t* ms = SGX_CAST(ms_get_sealed_data_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_encrypt_data = ms->ms_encrypt_data;
	size_t _len_encrypt_data = ms->ms_encrypt_data_len ;
	char* _in_encrypt_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_encrypt_data, _len_encrypt_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encrypt_data != NULL && _len_encrypt_data != 0) {
		_in_encrypt_data = (char*)malloc(_len_encrypt_data);
		if (_in_encrypt_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypt_data, _len_encrypt_data, _tmp_encrypt_data, _len_encrypt_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_encrypt_data[_len_encrypt_data - 1] = '\0';
		if (_len_encrypt_data != strlen(_in_encrypt_data) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = get_sealed_data_size((const char*)_in_encrypt_data);

err:
	if (_in_encrypt_data) free(_in_encrypt_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_seal_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_seal_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_seal_data_t* ms = SGX_CAST(ms_seal_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_blob = ms->ms_sealed_blob;
	uint32_t _tmp_data_size = ms->ms_data_size;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;
	const char* _tmp_encrypt_data = ms->ms_encrypt_data;
	size_t _len_encrypt_data = ms->ms_encrypt_data_len ;
	char* _in_encrypt_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);
	CHECK_UNIQUE_POINTER(_tmp_encrypt_data, _len_encrypt_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_blob, 0, _len_sealed_blob);
	}
	if (_tmp_encrypt_data != NULL && _len_encrypt_data != 0) {
		_in_encrypt_data = (char*)malloc(_len_encrypt_data);
		if (_in_encrypt_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypt_data, _len_encrypt_data, _tmp_encrypt_data, _len_encrypt_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_encrypt_data[_len_encrypt_data - 1] = '\0';
		if (_len_encrypt_data != strlen(_in_encrypt_data) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = seal_data(_in_sealed_blob, _tmp_data_size, (const char*)_in_encrypt_data);
	if (_in_sealed_blob) {
		if (memcpy_s(_tmp_sealed_blob, _len_sealed_blob, _in_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_blob) free(_in_sealed_blob);
	if (_in_encrypt_data) free(_in_encrypt_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_get_sealed_state_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_sealed_state_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_sealed_state_size_t* ms = SGX_CAST(ms_get_sealed_state_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = get_sealed_state_size();


	return status;
}

static sgx_status_t SGX_CDECL sgx_get_sealed_state(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_sealed_state_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_sealed_state_t* ms = SGX_CAST(ms_get_sealed_state_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_out = ms->ms_out;
	uint32_t _tmp_size = ms->ms_size;
	size_t _len_out = _tmp_size;
	uint8_t* _in_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_out, _len_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_out != NULL && _len_out != 0) {
		if ( _len_out % sizeof(*_tmp_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_out = (uint8_t*)malloc(_len_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out, 0, _len_out);
	}

	ms->ms_retval = get_sealed_state(_in_out, _tmp_size);
	if (_in_out) {
		if (memcpy_s(_tmp_out, _len_out, _in_out, _len_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_out) free(_in_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_unseal_state(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_unseal_state_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_unseal_state_t* ms = SGX_CAST(ms_ecall_unseal_state_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_sealed_blob = ms->ms_sealed_blob;
	size_t _tmp_data_size = ms->ms_data_size;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob);
		if (_in_sealed_blob == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_blob, _len_sealed_blob, _tmp_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_unseal_state((const uint8_t*)_in_sealed_blob, _tmp_data_size);

err:
	if (_in_sealed_blob) free(_in_sealed_blob);
	return status;
}

static sgx_status_t SGX_CDECL sgx_unseal_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_unseal_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_unseal_data_t* ms = SGX_CAST(ms_unseal_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_sealed_blob = ms->ms_sealed_blob;
	size_t _tmp_data_size = ms->ms_data_size;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;
	char* _tmp_out = ms->ms_out;
	size_t _len_out = _tmp_data_size;
	char* _in_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);
	CHECK_UNIQUE_POINTER(_tmp_out, _len_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob);
		if (_in_sealed_blob == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_blob, _len_sealed_blob, _tmp_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_out != NULL && _len_out != 0) {
		if ( _len_out % sizeof(*_tmp_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_out = (char*)malloc(_len_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out, 0, _len_out);
	}

	ms->ms_retval = unseal_data((const uint8_t*)_in_sealed_blob, _tmp_data_size, _in_out);
	if (_in_out) {
		if (memcpy_s(_tmp_out, _len_out, _in_out, _len_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_blob) free(_in_sealed_blob);
	if (_in_out) free(_in_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_free_all(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	free_all();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[11];
} g_ecall_table = {
	11,
	{
		{(void*)(uintptr_t)sgx_ecall_init, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_add, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_del, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_search, 0, 0},
		{(void*)(uintptr_t)sgx_get_sealed_data_size, 0, 0},
		{(void*)(uintptr_t)sgx_seal_data, 0, 0},
		{(void*)(uintptr_t)sgx_get_sealed_state_size, 0, 0},
		{(void*)(uintptr_t)sgx_get_sealed_state, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_unseal_state, 0, 0},
		{(void*)(uintptr_t)sgx_unseal_data, 0, 0},
		{(void*)(uintptr_t)sgx_free_all, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][11];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

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

sgx_status_t SGX_CDECL ocall_search(void* w_u_arr, void* w_id_arr, size_t count, size_t size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_w_u_arr = count * size;
	size_t _len_w_id_arr = count * size;

	ms_ocall_search_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_search_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(w_u_arr, _len_w_u_arr);
	CHECK_ENCLAVE_POINTER(w_id_arr, _len_w_id_arr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (w_u_arr != NULL) ? _len_w_u_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (w_id_arr != NULL) ? _len_w_id_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_search_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_search_t));
	ocalloc_size -= sizeof(ms_ocall_search_t);

	if (w_u_arr != NULL) {
		ms->ms_w_u_arr = (void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, w_u_arr, _len_w_u_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_w_u_arr);
		ocalloc_size -= _len_w_u_arr;
	} else {
		ms->ms_w_u_arr = NULL;
	}
	
	if (w_id_arr != NULL) {
		ms->ms_w_id_arr = (void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, w_id_arr, _len_w_id_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_w_id_arr);
		ocalloc_size -= _len_w_id_arr;
	} else {
		ms->ms_w_id_arr = NULL;
	}
	
	ms->ms_count = count;
	ms->ms_size = size;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

