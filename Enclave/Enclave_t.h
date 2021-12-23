#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_init(void);
void ecall_add(char* id_data, char* valuesPointer);
void ecall_del(char* id_str);
void ecall_search(char* id_str);
uint32_t get_sealed_data_size(const char* encrypt_data);
sgx_status_t seal_data(uint8_t* sealed_blob, uint32_t data_size, const char* encrypt_data);
uint32_t get_sealed_state_size(void);
sgx_status_t get_sealed_state(uint8_t* out, uint32_t size);
sgx_status_t ecall_unseal_state(const uint8_t* sealed_blob, size_t data_size);
sgx_status_t unseal_data(const uint8_t* sealed_blob, size_t data_size, char* out);
void free_all(void);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_add(void* u_arr, void* v_arr, size_t count, size_t size);
sgx_status_t SGX_CDECL ocall_search(void* w_u_arr, void* w_id_arr, size_t count, size_t size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
