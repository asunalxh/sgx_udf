#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_ADD_DEFINED__
#define OCALL_ADD_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_add, (void* u_arr, void* v_arr, size_t count, size_t size));
#endif
#ifndef OCALL_SEARCH_DEFINED__
#define OCALL_SEARCH_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_search, (void* w_u_arr, void* w_id_arr, size_t count, size_t size));
#endif

sgx_status_t ecall_init(sgx_enclave_id_t eid);
sgx_status_t ecall_add(sgx_enclave_id_t eid, char* id_data, char* valuesPointer);
sgx_status_t ecall_del(sgx_enclave_id_t eid, char* id_str);
sgx_status_t ecall_search(sgx_enclave_id_t eid, char* id_str);
sgx_status_t get_sealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, const char* encrypt_data);
sgx_status_t seal_data(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_blob, uint32_t data_size, const char* encrypt_data);
sgx_status_t get_sealed_state_size(sgx_enclave_id_t eid, uint32_t* retval);
sgx_status_t get_sealed_state(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* out, uint32_t size);
sgx_status_t ecall_unseal_state(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_blob, size_t data_size);
sgx_status_t unseal_data(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_blob, size_t data_size, char* out);
sgx_status_t free_all(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
