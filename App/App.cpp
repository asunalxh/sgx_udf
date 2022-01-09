/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <cstring>

#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include <fstream>

#include "mysql.h"
#include "my_alloc.h"

#include "AES.h"
#include "Base64.h"
#include "Util.h"

// mysearch结果的最长结果（字节）
#define RESULT_MAX_LENGTH 8192

string encode_key;
int eid = 1;
char *keyfilename = "keyfile.txt";
char *statefilename = "statefilterfile.txt";
long long anscount = 0;

unordered_map<string, string> M;
vector<string> ansList;
vector<vector<string>> vals;

extern "C"
{
    char* myinit(UDF_INIT *initid, UDF_ARGS *args,char* result,ulong* length ,char *is_null, char *error);
    my_bool myinit_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    char *myinsert(UDF_INIT *initid, UDF_ARGS *args,char* result,ulong* length ,char *is_null, char *error);
    my_bool myinsert_init(UDF_INIT *initid, UDF_ARGS *args, char *message);

    char* mysearch(UDF_INIT *initid, UDF_ARGS *args,char* result,ulong* length ,char *is_null, char *error);
    my_bool mysearch_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void mysearch_deinit(UDF_INIT *initid);

    char* mydel(UDF_INIT *initid, UDF_ARGS *args,char* result,ulong* length ,char *is_null, char *error);
    my_bool mydel_init(UDF_INIT *initid, UDF_ARGS *args, char *message);

    char* readdata(UDF_INIT *initid, UDF_ARGS *args,char* result,ulong* length ,char *is_null, char *error);
    my_bool readdata_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    char* getval(UDF_INIT *initid, UDF_ARGS *args,char* result,ulong* length ,char *is_null, char *error);
    my_bool getval_init(UDF_INIT *initid, UDF_ARGS *args, char *message);

    long long mycount(UDF_INIT *initid, UDF_ARGS *args,char *is_null, char *error);
    my_bool mycount_init(UDF_INIT *initid, UDF_ARGS *args, char *message);


    char* stringtest(UDF_INIT *initid, UDF_ARGS *args,char* result,ulong* length ,char *is_null, char *error);
    my_bool stringtest_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void stringtest_deinit(UDF_INIT * initid);

}

char* stringtest(UDF_INIT *initid, UDF_ARGS *args,char* result,ulong* length ,char *is_null, char *error){

    long long mysize = *((long long *)args->args[0]);
    string ans;
    for(int i = 0 ;i < mysize; i++){
        char x = 'a' + i % 26;
        ans += x;
    }

    strcpy(initid->ptr,ans.c_str());
    *length = ans.length();

    return initid->ptr;
}
my_bool stringtest_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    initid->ptr = new char[8192];
    return 0;
}

void stringtest_deinit(UDF_INIT * initid){
    delete[]  initid->ptr;
}


/* Global EID shared by multiple threads */

typedef struct _sgx_errlist_t
{
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED,
     "Unexpected error occurred.",
     NULL},
    {SGX_ERROR_INVALID_PARAMETER,
     "Invalid parameter.",
     NULL},
    {SGX_ERROR_OUT_OF_MEMORY,
     "Out of memory.",
     NULL},
    {SGX_ERROR_ENCLAVE_LOST,
     "Power transition occurred.",
     "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE,
     "Invalid enclave image.",
     NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID,
     "Invalid enclave identification.",
     NULL},
    {SGX_ERROR_INVALID_SIGNATURE,
     "Invalid enclave signature.",
     NULL},
    {SGX_ERROR_OUT_OF_EPC,
     "Out of EPC memory.",
     NULL},
    {SGX_ERROR_NO_DEVICE,
     "Invalid SGX device.",
     "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT,
     "Memory map conflicted.",
     NULL},
    {SGX_ERROR_INVALID_METADATA,
     "Invalid enclave metadata.",
     NULL},
    {SGX_ERROR_DEVICE_BUSY,
     "SGX device was busy.",
     NULL},
    {SGX_ERROR_INVALID_VERSION,
     "Enclave version was invalid.",
     NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE,
     "Enclave was not authorized.",
     NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS,
     "Can't open enclave file.",
     NULL},
};

/* Check error conditions for loading enclave */
void ret_error_support(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++)
    {
        if (ret == sgx_errlist[idx].err)
        {
            if (NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n",
               ret);
}

sgx_status_t initialize_enclave(const char *enclave_path, sgx_enclave_id_t *eid)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, NULL, NULL, eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        return ret;
    }
    return SGX_SUCCESS;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

static size_t get_file_size(const char *filename)
{
    std::ifstream ifs(filename, std::ios::in | std::ios::binary);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return -1;
    }
    ifs.seekg(0, std::ios::end);
    size_t size = (size_t)ifs.tellg();
    return size;
}

static bool write_buf_to_file(char *filename, const uint8_t *buf, size_t bsize, long offset)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ofstream ofs;
    ofs.open(filename, std::ios::binary | std::ios::out);
    if (!ofs.is_open())
        return false;
    ofs.write(reinterpret_cast<const char *>(buf), bsize);
    ofs.flush();
    ofs.close();
    return true;
}

bool read_file_to_buf(char *filename, uint8_t *buf, size_t bsize)
{
    if (filename == NULL || buf == NULL || bsize == 0)
    {
        std::cout << "There is no state information, Please insert" << endl;
        return false;
    }
    std::ifstream ifs;
    ifs.open(filename, std::ios::binary | std::ios::in);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    if (!ifs.is_open())
        return false;
    ifs.read(reinterpret_cast<char *>(buf), bsize);
    if (ifs.fail())
    {
        std::cout << "Failed to read the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ifs.close();
    return true;
}


void ocall_add(void *u_arr_pointer, void *v_arr_pointer, size_t count, size_t size) {
    DataStruct *u_arr = (DataStruct *) u_arr_pointer;
    DataStruct *v_arr = (DataStruct *) v_arr_pointer;
    for (int i = 0; i < count; i++) {
        M[u_arr[i].content] = v_arr[i].content;
        // cout << u_arr[i].content << ' ' << u_arr[i].content << endl;
    }
}

void ocall_search(void *w_u_arr_pointer, void *w_id_arr_pointer, size_t count, size_t size)
{
    DataStruct *w_u_arr = (DataStruct *)w_u_arr_pointer;
    DataStruct *w_id_arr = (DataStruct *)w_id_arr_pointer;
    cout << "count " << count << endl;
    for (int i = 0; i < count; i++)
    {
        cout << w_u_arr[i].content << ' ' << w_id_arr[i].content << endl;
        string id = Dec(w_id_arr[i].content, M[w_u_arr[i].content]);
        // cout << "result " << id << endl;
        ansList.push_back(id);
        anscount ++;
    }
}

bool seal_state(sgx_enclave_id_t eid_unseal)
{
    uint32_t sealed_state_size = 0;
    sgx_status_t ret = get_sealed_state_size(eid_unseal, &sealed_state_size);

    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    else if (sealed_state_size == UINT32_MAX)
    {

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    uint8_t *temp_state_sealed_buf = (uint8_t *)malloc(sealed_state_size);
    if (temp_state_sealed_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    sgx_status_t sealstretval;
    ret = get_sealed_state(eid_unseal, &sealstretval, temp_state_sealed_buf, sealed_state_size);

    if (ret != SGX_SUCCESS)
    {
        cout << "error 1\n";
        ret_error_support(ret);

        free(temp_state_sealed_buf);

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    else if (sealstretval != SGX_SUCCESS)
    {
        cout << "error 2\n";
        ret_error_support(sealstretval);
        free(temp_state_sealed_buf);

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    if (write_buf_to_file(statefilename, temp_state_sealed_buf, sealed_state_size, 0) == false)
    {
        std::cout << "Failed to save the sealed data blob to \"" << statefilename << "\"" << std::endl;

        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    free(temp_state_sealed_buf);
    return true;
}

bool unseal_state(sgx_enclave_id_t eid_unseal)
{
    size_t stfsize = get_file_size(statefilename);
    if (stfsize == 0)
    {
        return true;
    }
    if (stfsize == (size_t)-1)
    {
        std::cout << "Failed to get the file size of \"" << statefilename << "\"" << std::endl;

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    uint8_t *st_temp_buf = (uint8_t *)malloc(stfsize);
    if (st_temp_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    if (read_file_to_buf(statefilename, st_temp_buf, stfsize) == false)
    {
        std::cout << "Failed to read the sealed data blob from \"" << statefilename << "\"" << std::endl;
        free(st_temp_buf);

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    // Unseal the sealed blob
    sgx_status_t stretval;
    sgx_status_t ret = ecall_unseal_state(eid_unseal, &stretval, st_temp_buf, stfsize);
    if (ret != SGX_SUCCESS)
    {
        printf("unseal error 1\n");
        ret_error_support(ret);
        free(st_temp_buf);

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    else if (stretval != SGX_SUCCESS)
    {
        printf("unseal error 2\n");
        ret_error_support(stretval);
        //        free(st_temp_buf);
        //        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    //
    free(st_temp_buf);
    return true;
}

bool getKey(sgx_enclave_id_t eid_unseal)
{
    size_t stfsize = get_file_size(keyfilename);
    if (stfsize == 0)
    {
        return true;
    }
    if (stfsize == (size_t)-1)
    {
        std::cout << "Failed to get the file size of \"" << keyfilename << "\"" << std::endl;

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    uint8_t *st_temp_buf = (uint8_t *)malloc(stfsize);
    if (st_temp_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    if (read_file_to_buf(keyfilename, st_temp_buf, stfsize) == false)
    {
        std::cout << "Failed to read the sealed data blob from \"" << keyfilename << "\"" << std::endl;
        free(st_temp_buf);

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    char *out = new char[stfsize];

    // Unseal the sealed blob
    sgx_status_t stretval;
    sgx_status_t ret = unseal_data(eid_unseal, &stretval, st_temp_buf, stfsize, out);
    if (ret != SGX_SUCCESS)
    {
        printf("unseal error 1\n");
        ret_error_support(ret);
        free(st_temp_buf);

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    else if (stretval != SGX_SUCCESS)
    {
        printf("unseal error 2\n");
        ret_error_support(stretval);
        //        free(st_temp_buf);
        //        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    encode_key = out;
    delete[] out;
    //
    free(st_temp_buf);
    return true;
}

string insertData(char *id, char *P_BRAND)
{
    /* Initialize the enclave */
    sgx_enclave_id_t eid_unseal = eid++;
    initialize_enclave(ENCLAVE_FILENAME, &eid_unseal);

    ecall_init(eid_unseal);

    unseal_state(eid_unseal);

    getKey(eid_unseal);

    ecall_add(eid_unseal, id, P_BRAND);

    seal_state(eid_unseal);

    sgx_destroy_enclave(eid_unseal);

    return Enc(encode_key, RndPt(P_BRAND));
}


void searchData(char* id)
{

    ansList.clear();
    anscount = 0;
    /* Initialize the enclave */
    sgx_enclave_id_t eid_unseal = eid++;
    initialize_enclave(ENCLAVE_FILENAME, &eid_unseal);

    ecall_init(eid_unseal);

    unseal_state(eid_unseal);

    getKey(eid_unseal);

    // char *id = new char[RAND_LEN];
    // strcpy(id, word.c_str());
    ecall_search(eid_unseal, id);
    // delete[] id;
    seal_state(eid_unseal);

    //    free_all(eid_unseal);
    sgx_destroy_enclave(eid_unseal);
}

void delData(char* id)
{
    /* Initialize the enclave */
    sgx_enclave_id_t eid_unseal = eid++;
    initialize_enclave(ENCLAVE_FILENAME, &eid_unseal);

    ecall_init(eid_unseal);

    unseal_state(eid_unseal);

    // char *id = new char[RAND_LEN];
    // strcpy(id, word.c_str());
    ecall_del(eid_unseal, id);
    // delete[] id;

    seal_state(eid_unseal);

    //    free_all(eid_unseal);
    sgx_destroy_enclave(eid_unseal);
}

bool init()
{
    /* Initialize the enclave */
    sgx_enclave_id_t eid_unseal = eid++;
    initialize_enclave(ENCLAVE_FILENAME, &eid_unseal);
    ecall_init(eid_unseal);

    char key[] = "abcdefghijklmnop";

    uint32_t sealed_key_size = 0;
    sgx_status_t ret = get_sealed_data_size(eid_unseal, &sealed_key_size, key);

    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    else if (sealed_key_size == UINT32_MAX)
    {

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    uint8_t *temp_key_sealed_buf = (uint8_t *)malloc(sealed_key_size);
    if (temp_key_sealed_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    sgx_status_t sealstretval;
    ret = seal_data(eid_unseal, &sealstretval, temp_key_sealed_buf, sealed_key_size, key);

    if (ret != SGX_SUCCESS)
    {
        cout << "error 1\n";
        ret_error_support(ret);
        free(temp_key_sealed_buf);

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    else if (sealstretval != SGX_SUCCESS)
    {
        cout << "error 2\n";
        ret_error_support(sealstretval);
        free(temp_key_sealed_buf);

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    if (write_buf_to_file(keyfilename, temp_key_sealed_buf, sealed_key_size, 0) == false)
    {
        std::cout << "Failed to save the sealed data blob to \"" << keyfilename << "\"" << std::endl;

        //        free_all(eid_unseal);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    free(temp_key_sealed_buf);

    seal_state(eid_unseal);

    //    free_all(eid_unseal);
    sgx_destroy_enclave(eid_unseal);

    return true;
}

char* myinit(UDF_INIT *initid, UDF_ARGS *args,char* result,ulong* length ,char *is_null, char *error){
    M.clear(); 
    string ans = init() ? M.clear(), "初始化成功" : "初始化失败";
    strcpy(result,ans.c_str());
    *length = ans.length();
    return result;
}
my_bool myinit_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    return 0;
}

char* mydel(UDF_INIT *initid, UDF_ARGS *args,char* result,ulong* length ,char *is_null, char *error){
    // int id_int= *((long long* )args->args[0]);
    // string id_str = to_string(id_int);
    // char* id = new char[id_str.length() + 1];
    // strcpy(id,id_str.c_str());

    char* id= (char* )args->args[0];
    delData(id);
    strcpy(result,id);
    *length = strlen(id) + 1;

    // delete id;

    return result;
}
my_bool mydel_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    return 0;
}


char *myinsert(UDF_INIT *initid, UDF_ARGS *args,char* result,ulong* length ,char *is_null, char *error)
{
    // int id_int= *((long long* )args->args[0]);
    // string id_str = to_string(id_int);
    // char* id = new char[id_str.length() + 1];
    // strcpy(id,id_str.c_str());

    char* id = (char*)args->args[0];
    char *val = (char*)args->args[1];
    string ans = insertData(id,val);
    strcpy(result,ans.c_str());
    *length = ans.length();

    // delete id;

    return result;
}

my_bool myinsert_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return 0;
}

char* mysearch(UDF_INIT *initid, UDF_ARGS *args,char* result,ulong* length ,char *is_null, char *error){
    char* P_BRAND = (char*) args->args[0];
    searchData(P_BRAND);
    string ans="";
    for(string x : ansList){
        ans = ans + " " + x;
    }

    strcpy(initid->ptr,ans.c_str());
    *length = ans.length();

    return initid->ptr;
}
my_bool mysearch_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    initid->ptr = new char[RESULT_MAX_LENGTH];
    return 0;
}

void mysearch_deinit(UDF_INIT *initid){
    delete[] initid->ptr;
}



char* readdata(UDF_INIT *initid, UDF_ARGS *args,char* result,ulong* length ,char *is_null, char *error){
    vals.clear();
    char* address = args->args[0];
    ifstream in(address,ios::in);

    if(!in){
        char* meg = "打开文件时失败";
        strcpy(result,meg);
        *length = strlen(meg);
        return result;
    }

    string str;
    while(getline(in,str)){
        vector<string> fields = splitBy(str,',');
        vals.push_back(fields);
    }

    char* meg = "已读取所有数据";
    strcpy(result,meg);
    *length = strlen(meg);
    return result;
}

my_bool readdata_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    return 0;
}

char* getval(UDF_INIT *initid, UDF_ARGS *args,char* result,ulong* length ,char *is_null, char *error){
    int i = *((long long*) args->args[0]);
    int j = *((long long*) args->args[1]);

    string val = vals[i][j];
    strcpy(result,val.c_str());
    *length = val.length();
    return result;
}

my_bool getval_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    return 0;
}

long long mycount(UDF_INIT *initid, UDF_ARGS *args,char *is_null, char *error){
    char* str = (char* )args->args[0];
    searchData(str);
    return anscount;
}
my_bool mycount_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    return 0;
}


int SGX_CDECL
main(int argc, char *argv[])
{
    init();
    vals.clear();
    ifstream in("PART.csv",ios::in);

    string str;
    while(getline(in,str)){
        vector<string> fields = splitBy(str,',');
        vals.push_back(fields);
    }

    for(int i = 0 ; i < 5000;i ++){
        string id_str  = vals[i][0];
        string val_str = vals[i][1];

        cout << id_str << ' ' << val_str << endl;

        char* id = new char[id_str.length() + 1];
        strcpy(id,id_str.c_str());

        char* val = new char[val_str.length() + 1];
        strcpy(val,val_str.c_str());

        insertData(id,val);
    }
}


//sudo cp app.so /opt/lampp/lib/mysql/plugin/
//sudo cp enclave.signed.so /usr/lib