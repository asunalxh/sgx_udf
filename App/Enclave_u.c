#include "Enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_search(void* pms)
{
	ms_ocall_search_t* ms = SGX_CAST(ms_ocall_search_t*, pms);
	ocall_search(ms->ms_w_u_arr, ms->ms_w_id_arr, ms->ms_count, ms->ms_size);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_Enclave = {
	2,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_search,
	}
};
sgx_status_t ecall_init(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_add(sgx_enclave_id_t eid, char* id_data, char* valuesPointer, char* u_arr, char* v_arr, size_t out_size)
{
	sgx_status_t status;
	ms_ecall_add_t ms;
	ms.ms_id_data = id_data;
	ms.ms_id_data_len = id_data ? strlen(id_data) + 1 : 0;
	ms.ms_valuesPointer = valuesPointer;
	ms.ms_valuesPointer_len = valuesPointer ? strlen(valuesPointer) + 1 : 0;
	ms.ms_u_arr = u_arr;
	ms.ms_v_arr = v_arr;
	ms.ms_out_size = out_size;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_del(sgx_enclave_id_t eid, char* id_str, size_t id_len)
{
	sgx_status_t status;
	ms_ecall_del_t ms;
	ms.ms_id_str = id_str;
	ms.ms_id_len = id_len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_search(sgx_enclave_id_t eid, char* id_str)
{
	sgx_status_t status;
	ms_ecall_search_t ms;
	ms.ms_id_str = id_str;
	ms.ms_id_str_len = id_str ? strlen(id_str) + 1 : 0;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t get_sealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, const char* encrypt_data)
{
	sgx_status_t status;
	ms_get_sealed_data_size_t ms;
	ms.ms_encrypt_data = encrypt_data;
	ms.ms_encrypt_data_len = encrypt_data ? strlen(encrypt_data) + 1 : 0;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t seal_data(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_blob, uint32_t data_size, const char* encrypt_data)
{
	sgx_status_t status;
	ms_seal_data_t ms;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	ms.ms_encrypt_data = encrypt_data;
	ms.ms_encrypt_data_len = encrypt_data ? strlen(encrypt_data) + 1 : 0;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_sealed_state_size(sgx_enclave_id_t eid, uint32_t* retval)
{
	sgx_status_t status;
	ms_get_sealed_state_size_t ms;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_sealed_state(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* out, uint32_t size)
{
	sgx_status_t status;
	ms_get_sealed_state_t ms;
	ms.ms_out = out;
	ms.ms_size = size;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_unseal_state(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_blob, size_t data_size)
{
	sgx_status_t status;
	ms_ecall_unseal_state_t ms;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t unseal_data(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_blob, size_t data_size, char* out)
{
	sgx_status_t status;
	ms_unseal_data_t ms;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	ms.ms_out = out;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t free_all(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, NULL);
	return status;
}

