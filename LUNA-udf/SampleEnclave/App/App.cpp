/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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
#pragma once

#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <map>
#include <vector>
#include <algorithm>
#include <fstream>
//#include <ifstream>
#include <iostream>
#include <sstream>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "Enclave_u.h"
#include "ErrorSupport.h"
#include "mysql.h"
#include "my_alloc.h"
#include "oneitem.h"
#include "App.h"

using namespace std;


char ai[100] = {0};
extern "C"
{
    
    long long test(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *err);
    my_bool test_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void test_deinit(UDF_INIT* initid);

    long long keyinit(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *err);
    my_bool keyinit_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void keyinit_deinit(UDF_INIT* initid);

    char* GetKw(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
    my_bool GetKw_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void GetKw_deinit(UDF_INIT* initid);

    char* prenc(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
    my_bool prenc_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void prenc_deinit(UDF_INIT* initid);

    char* prdel(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
    my_bool prdel_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void prdel_deinit(UDF_INIT* initid);

    char* search(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
    my_bool search_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void search_deinit(UDF_INIT* initid);
}

my_bool test_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    return 0;
}


sgx_enclave_id_t eid = 0;

char lserr[100] = {0};
map<string, string> indMap;
map<string, string> wMap;
map<string, string> delMap;
enc_dblp eitem;
int id = 1;
dblp item;
sdblp sitem;
bool ifinsert = false;
char BlockInd[256] = {0};
char BlockW[256] = {0};
vector<string> vals;

char keyfilename[100] = "keyfile.txt";
char statefilename[100] = "stfile.txt";
char delfilename[100] = "delfile.txt";
//char datafile[100] = "part.txt";
char datafile[100] = "crime.txt";
#define RESULT_MAX_LENGTH 655350

size_t get_file_size(const char *filename)
{
    std::ifstream ifs(filename, std::ios::in | std::ios::binary);
    if (!ifs.good())
    {
        return -1;
    }
    ifs.seekg(0, std::ios::end);
    size_t size = (size_t)ifs.tellg();
    return size;
}

bool read_file_to_buf(char *filename, uint8_t *buf, size_t bsize)
{
    if (filename == NULL || buf == NULL || bsize == 0)
    {
        return false;
    }
    std::ifstream ifs;
    ifs.open(filename, std::ios::binary | std::ios::in);
    if (!ifs.good())
    {
        return false;
    }
    if (!ifs.is_open())
        return false;
    ifs.read(reinterpret_cast<char *>(buf), bsize);
    if (ifs.fail())
    {
        return false;
    }
    ifs.close();
    return true;
}

bool write_buf_to_file(char *filename, const uint8_t *buf, size_t bsize, long offset)
{
    if (filename == NULL || buf == NULL || bsize == 0){
        return false;
    }
    std::ofstream ofs;
    ofs.open(filename, std::ios::binary | std::ios::out);
    if (!ofs.is_open()){
        return false;
    }
    ofs.write(reinterpret_cast<const char *>(buf), bsize);
    ofs.flush();
    ofs.close();
    return true;
}
bool write_buf()
{
    std::ofstream ofs(statefilename, std::ios::binary | std::ios::out);
    ofs.close();
    return true;
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

bool seal_and_save_data(char *encrypt_data, char *filename)
{
    
    // Load the enclave for sealing
    sgx_status_t ret = initialize_enclave(ENCLAVE_FILENAME, &eid);
    if (ret != SGX_SUCCESS)
    {
        return false;
    }
    // Get the sealed data size
    uint32_t sealed_data_size = 0;
    ret = get_sealed_data_size(eid, &sealed_data_size, encrypt_data);
    if (ret != SGX_SUCCESS)
    {
        sgx_destroy_enclave(eid);
        return false;
    }
    else if (sealed_data_size == UINT32_MAX)
    {
        sgx_destroy_enclave(eid);
        return false;
    }

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if (temp_sealed_buf == NULL)
    {
        sgx_destroy_enclave(eid);
        return false;
    }
    sgx_status_t retval;
    ret = seal_data(eid, &retval, temp_sealed_buf, sealed_data_size, encrypt_data);
    if (ret != SGX_SUCCESS)
    {
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid);
        return false;
    }
    else if (retval != SGX_SUCCESS)
    {
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid);
        return false;
    }

    // Save the sealed blob
    if (write_buf_to_file(filename, temp_sealed_buf, sealed_data_size, 0) == false)
    {
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid);
        return false;
    }

    free(temp_sealed_buf);
    sgx_destroy_enclave(eid);

    return true;
}

bool getKey(sgx_enclave_id_t eid)
{
    size_t keyfsize = get_file_size(keyfilename);
    if (keyfsize == 0)
    {
        return true;
    }
    if (keyfsize == (size_t)-1)
    {
        return false;
    }
    uint8_t *key_temp_buf = (uint8_t *)malloc(keyfsize);

    if (key_temp_buf == NULL)
    {
        return false;
    }
    if (read_file_to_buf(keyfilename, key_temp_buf, keyfsize) == false)
    {
        free(key_temp_buf);
        return false;
    }

    // Unseal the sealed blob
    sgx_status_t keyretval;
    sgx_status_t ret = unseal_state(eid, &keyretval, key_temp_buf, keyfsize);
    if (ret != SGX_SUCCESS)
    {
        free(key_temp_buf);
        return false;
    }
    else if (keyretval != SGX_SUCCESS)
    {
        free(key_temp_buf);
        return false;
    }
    
    ret = parsekey(eid, &keyretval);
    if (ret != SGX_SUCCESS)
    {
        free(key_temp_buf);
        return false;
    }
    else if (keyretval != SGX_SUCCESS)
    {
        free(key_temp_buf);
        return false;
    }
    free(key_temp_buf);
    return true;
}

bool getStat(sgx_enclave_id_t eid)
{
    size_t stfsize = get_file_size(statefilename);
    if (stfsize == 0)
    {
        return true;
    }
    if (stfsize == (size_t)-1)
    {
        return false;
    }

    uint8_t *st_temp_buf = (uint8_t *)malloc(stfsize);
    if (st_temp_buf == NULL)
    {
        return false;
    }

    if (read_file_to_buf(statefilename, st_temp_buf, stfsize) == false)
    {
        free(st_temp_buf);
        return false;
    }

    // Unseal the sealed blob
    sgx_status_t stretval;
    sgx_status_t ret = unseal_state(eid, &stretval, st_temp_buf, stfsize);
    if (ret != SGX_SUCCESS)
    {
        free(st_temp_buf);
        return false;
    }
    else if (stretval != SGX_SUCCESS)
    {
        free(st_temp_buf);
        return false;
    }
    free(st_temp_buf);
    return true;
}

bool getDel(sgx_enclave_id_t eid)
{
    size_t delfsize = get_file_size(delfilename);
    if (delfsize == 0)
    {
        return true;
    }
    if (delfsize == (size_t)-1)
    {
        return false;
    }

    uint8_t *del_temp_buf = (uint8_t *)malloc(delfsize);
    if (del_temp_buf == NULL)
    {
        return false;
    }

    if (read_file_to_buf(delfilename, del_temp_buf, delfsize) == false)
    {
        free(del_temp_buf);
        return false;
    }

    // Unseal the sealed blob
    sgx_status_t delretval;
    sgx_status_t ret = unseal_dellist(eid, &delretval, del_temp_buf, delfsize);
    if (ret != SGX_SUCCESS)
    {
        free(del_temp_buf);
        return false;
    }
    else if (delretval != SGX_SUCCESS)
    {
        free(del_temp_buf);
        return false;
    }
    free(del_temp_buf);
    return true;
}


bool sealState(sgx_enclave_id_t eid)
{
    uint32_t sealed_state_size = 0;
    sgx_status_t ret = get_sealed_state_size(eid, &sealed_state_size);
    if (ret != SGX_SUCCESS)
    {
        return false;
    }
    else if (sealed_state_size == UINT32_MAX)
    {
        return false;
    }

    uint8_t *temp_state_sealed_buf = (uint8_t *)malloc(sealed_state_size);
    if (temp_state_sealed_buf == NULL)
    {
        return false;
    }
    sgx_status_t sealstretval;
    ret = seal_state(eid, &sealstretval, temp_state_sealed_buf, sealed_state_size);
    if (ret != SGX_SUCCESS)
    {
        free(temp_state_sealed_buf);
        return false;
    }
    else if (sealstretval != SGX_SUCCESS)
    {
        free(temp_state_sealed_buf);
        return false;
    }
    if (write_buf_to_file(statefilename, temp_state_sealed_buf, sealed_state_size, 0) == false)
    {
        return false;
    }
    return true;
}

void ocall_insertidx_err(char *inerr){
    memset(lserr, 0, sizeof(lserr));
    strcpy(lserr, inerr);
}
bool read_unseal_insert(char *keyfilename, char *statefilename, char *keyword, int keysize, int id, char *BlockInd, int lengthInd, char *BlockW, int lengthW)
{
    sgx_status_t ret, stretval;
    if (!getKey(eid)){
        return false;
    }
    if (!getStat(eid)){
        return false;
    }
    
    ret = insertidx(eid, &stretval, keyword, keysize, id, BlockInd, lengthInd, BlockW, lengthW);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return false;
    }
    else if (stretval != SGX_SUCCESS)
    {
        ret_error_support(stretval);
        return false;
    }
    if (!sealState(eid)){
        return false;
    }
    return true;
}



void ocall_print_string(const char *str)
{
    printf("%s", str);
}

bool parse_BlockInd(char *BlockInd, char *labelInd, char *labelwStar)
{
    if (strlen(BlockInd) == 0){
        return false;
    }
    memcpy(labelInd, BlockInd, 24);
    labelInd[24] = '\0';
    memcpy(labelwStar, BlockInd + 24, strlen(BlockInd) - 24);
    labelwStar[strlen(BlockInd) - 24] = '\0';

    return true;
}

bool parse_BlockW(char *BlockW, char *labelw, char *res)
{
    if (strlen(BlockW) == 0){
        return false;
    }
    memcpy(labelw, BlockW, 24);
    labelw[24] = '\0';
    memcpy(res, BlockW + 24, strlen(BlockW) - 24);
    res[strlen(BlockW) - 24] = '\0';
    return true;
}

bool parse_BlockDel(char *BlockDel, char *labeldel, char *labelwdel)
{
    memcpy(labeldel, BlockDel, 24);
    labeldel[24] = '\0';
    memcpy(labelwdel, BlockDel + 24, strlen(BlockDel) - 24);
    labelwdel[strlen(BlockDel) - 24] = '\0';
    return true;
}

bool initKey()
{
    char encrypt_data[BUFSIZ] = "asdfwetyhjuytrfd*";
    char aad_mac_text[BUFSIZ] = "gfdertfghjkuyrtg*|";
    strcat(encrypt_data, aad_mac_text);
    if (seal_and_save_data(encrypt_data, keyfilename) == false)
    {
        return false;
    }
    return true;
}

bool insertone()
{
    char labelInd[25] = {0};
    char labelwStar[240] = {0};
    char labelw[25] = {0};
    char res[128] = {0};
    if (!parse_BlockInd(BlockInd, labelInd, labelwStar)){
        return false;
    }
    if (!parse_BlockW(BlockW, labelw, res)){
        return false;
    }

    indMap.insert(map<string, string>::value_type(labelInd, labelwStar));
    pair<map<string, string>::iterator, bool> ret;
    ret = wMap.insert(map<string, string>::value_type(labelw, res));
    
    return true;
}

my_bool keyinit_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    sgx_status_t ret = initialize_enclave(ENCLAVE_FILENAME, &eid);
    if (ret != SGX_SUCCESS)
    {
        return NULL;
    }
    return 0;
}
long long keyinit(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *err){
    if (initKey()){
        return 1;
    } else {
        return 0;
    }
}

void keyinit_deinit(UDF_INIT* initid){
    sgx_destroy_enclave(eid);
    return;
}



my_bool GetKw_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    return 0;
}


char* GetKw(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    vals.clear();
    //char* address = (char*)args->args[0];
    ifstream in(datafile, ios::in);

    if(!in){
        char* meg = "Wrong Open";
        strcpy(result,meg);
        *length = strlen(meg);
        return result;
    }

    string str;
    char kw[9] = {0};
    while(getline(in, str)){
        istringstream sin(str); 
        string field;
        getline(sin, field, ',');

        vals.push_back(field);
    }

    char* meg = "Success";
    strcpy(result,meg);
    *length = strlen(meg);
    return result;
}

void GetKw_deinit(UDF_INIT* initid){
    //return;
}


my_bool prenc_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    sgx_status_t ret = initialize_enclave(ENCLAVE_FILENAME, &eid);
    if (ret != SGX_SUCCESS)
    {
        return NULL;
    }
    return 0;
}

//char* prenc(int i)
char* prenc(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)//udf
{
    
    dblp item;
    sdblp sitem;
    enc_dblp eitem;
    int i = *((long long *)args->args[0]);
    item.journal = vals[i];
    item.id = i;
    eitem.id = i;
    sitem.sjournal = RndPt(item.journal);
    eitem.enc_journal = EncryptionAES(sitem.sjournal);
    
    if (!read_unseal_insert(keyfilename, statefilename, (char *)(item.journal.c_str()), 25, i, BlockInd, 256, BlockW, 256)){
    
        return NULL;
        
    }
    if (!insertone()){
        return NULL;
    }
    if (strlen(BlockInd) == 0){
        return NULL;
    }
    
    *length = (unsigned long)strlen((eitem.enc_journal.c_str()));
    memcpy(result, (eitem.enc_journal).c_str(), *length);
    
    return result;
}
void prenc_deinit(UDF_INIT* initid){
    sgx_destroy_enclave(eid);
    return;
}

char* prdel(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
//bool deleteidx(int ind)
{
    int ind = *((long long *)args->args[0]);
    char labelInd[25] = {0};
    sgx_status_t ret, retval;
    
    getKey(eid);
    
    char cind[10] = {0};
    memcpy(cind, to_string(ind).c_str(), strlen(to_string(ind).c_str()));
    cind[strlen(to_string(ind).c_str())] = '\0';
    ret = genLabelInd(eid, &retval, cind, strlen(cind), labelInd, 24);

    if (ret != SGX_SUCCESS)
    {
        return NULL;
    }
    if (retval != SGX_SUCCESS)
    {
        return NULL;
    }
    
    string slabelInd(labelInd);

    map<string, string>::iterator iter;
    string slabelwStar;
    iter = indMap.find(slabelInd);
    if (iter != indMap.end())
    {
        slabelwStar = iter->second;
    }
    else
    {
        return NULL;
    }

    if (slabelwStar.length() == 0)
    {
        return NULL;
    }
 
    char* labelwStar = new char[145];
    memset(labelwStar, 0, sizeof(labelwStar));
    memcpy(labelwStar, slabelwStar.c_str(), slabelwStar.length());
    labelwStar[slabelwStar.length()] = '\0';

    

    int n = indMap.erase(slabelInd);
    if (n == 0)
    {
        return NULL;
    }

    
    char labelw[25] = {0};
    sgx_status_t retval1;
    
    getStat(eid);
    getDel(eid);
    
    char* BlockDel = new char[73];
    memset(BlockDel, 0, 73);
    char* wdellabel = new char[400000];
    memset(wdellabel, 0, 400000);
    ret = genlabelw(eid, &retval1, labelwStar, 144, cind, strlen(cind), labelw, 25, BlockDel, 73, wdellabel, 400000);
    
    
    sealState(eid);
    
    labelw[strlen(labelw)] = '\0';

    
    int n2 = wMap.erase(labelw);
    

    char* labeldel = new char[25];
    memset(labeldel, 0, 25);
    char* labelwdel = new char[72];
    memset(labelwdel, 0, 72);
    if (strlen(BlockDel) > 0)
    { 
        parse_BlockDel(BlockDel, labeldel, labelwdel);
        string slabeldel = labeldel;
        string slabelwdel = labelwdel;
        delMap.insert(map<string, string>::value_type(slabeldel, slabelwdel));
    }
    else
    { 
        
    }

    
    wdellabel[strlen(wdellabel)] = '\0';
    if (strlen(wdellabel) != 0)
    {
        string swdel = wdellabel;
        char lab[25] = {0};
        for (int k = 0; k < (strlen(wdellabel) / 24); k++)
        {
            memcpy(lab, wdellabel + k * 24, 24);
            string slab = lab;
            lab[24] = '\0';
            int n4 = delMap.erase(slab);
            if (n4 == 0)
            {
                
                continue;
            }
        }
    }

    if (ret != SGX_SUCCESS)
    {
        return NULL;
    }
    if (retval1 != SGX_SUCCESS)
    {
        return NULL;
    }

    
    uint32_t sealed_del_size = 0;
    ret = get_sealed_dellist_size(eid, &sealed_del_size);
    if (ret != SGX_SUCCESS)
    {
        return NULL;
    }
    else if (sealed_del_size == UINT32_MAX)
    {
        return NULL;
    }

    uint8_t *temp_state_del_buf = (uint8_t *)malloc(sealed_del_size);
    if (temp_state_del_buf == NULL)
    {
        return NULL;
    }
    sgx_status_t sealdelretval;
    ret = seal_DList(eid, &sealdelretval, temp_state_del_buf, sealed_del_size);
    if (ret != SGX_SUCCESS)
    {
        free(temp_state_del_buf);
        return NULL;
    }
    else if (sealdelretval != SGX_SUCCESS)
    {
        free(temp_state_del_buf);
        return NULL;
    }
    if (write_buf_to_file(delfilename, temp_state_del_buf, sealed_del_size, 0) == false)
    {
        return NULL;
    }

    

    delete[] labelwStar;
    delete[] BlockDel;
    delete[] wdellabel;
    delete[] labeldel;
    delete[] labelwdel;
    string ls(to_string(ind));
    memset(result, 0, sizeof(result));
    *length = (unsigned long)strlen(ls.c_str());
    memcpy(result, (ls).c_str(), *length);
    return result;
}

my_bool prdel_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    sgx_status_t ret = initialize_enclave(ENCLAVE_FILENAME, &eid);
    if (ret != SGX_SUCCESS)
    {
        return NULL;
    }
    return 0;
}


void prdel_deinit(UDF_INIT* initid){
    sgx_destroy_enclave(eid);
}

my_bool search_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    initid->ptr = new char[RESULT_MAX_LENGTH];
    sgx_status_t ret = initialize_enclave(ENCLAVE_FILENAME, &eid);
    if (ret != SGX_SUCCESS)
    {
        return NULL;
    }
    return 0;
}




char* search(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error){
//char* search(char *keyword){
    char *keyword = (char*)args->args[0];
    sgx_status_t ret, retval;
    
    if (!getKey(eid)){
        return NULL;
    }
    
    
    if (!getStat(eid)){
        return NULL;
    }
    if (!getDel(eid)){
        return NULL;
    }
    
    
    char* strdel = new char[240000];
    memset(strdel, 0, 240000);
    ret = genLabeldel(eid, &retval, keyword, 100, strdel, 240000);
    
    if (ret != SGX_SUCCESS)
    {
        return NULL;
    }
    else if (retval != SGX_SUCCESS)
    {
        return NULL;
    }

    
    int i;
    char* labeldel = new char[25];
    memset(labeldel, 0, 25);
    string slabeldel, slabelwdel;
    
    char *labelSetOut = new char[240000];
    memset(labelSetOut, 0, 240000);
    char *sign = "*";
    map<string, string>::iterator iter;
    for (i = 0; i < (strlen(strdel) / 24); i++)
    {
        memcpy(labeldel, strdel + i * 24, 24);
        
        slabeldel = labeldel;

        iter = delMap.find(slabeldel);
        if (iter != delMap.end())
        {
            slabelwdel = iter->second;
        }
        else
        {
            
        }

        memcpy(labelSetOut + strlen(labelSetOut), slabelwdel.c_str(), slabelwdel.length());
        memcpy(labelSetOut + strlen(labelSetOut), sign, 1);
    }
    sgx_status_t getdSetretrval,retr;


    
    char* labelRes = new char[650000];
    memset(labelRes, 0, 650000);
    ret = GetLabelRes(eid, &getdSetretrval, keyword, 25, labelSetOut, 160000, labelRes, 650000);
    int len = strlen(labelRes);
    
    char* res = new char[640000];
    memset(res, 0, 640000);
    char* labelw = new char[25];
    memset(labelw, 0, 25);
    
    string sres;
    int res_sum = 0;
    for (i = 0; i < len / 24; i++)
    {
        memcpy(labelw, labelRes + i * 24, 24);
        labelw[24] = '\0';
        string slabelw = labelw;

        
        iter = wMap.find(slabelw);
        if (iter != wMap.end())
        {
            sres = iter->second;
            memcpy(res + strlen(res), sres.c_str(), sres.length());
            memcpy(res + strlen(res), "**", 2);
            res_sum++;
        }
        else
        {
            
        }

        
    }
    
    char *finres = new char[200000];
    memset(finres, 0, 200000);
    
    ret = getInd(eid, &retr, keyword, 25, res, 320000, finres, 200000);
    
    
    string ls(to_string(res_sum).c_str());
    strcpy(initid->ptr,ls.c_str());
    *length = ls.length();

    delete[] strdel;
    delete[] labeldel;
    delete[] labelSetOut;
    delete[] labelRes;
    delete[] res;
    delete[] labelw;
    delete[] finres;
    return initid->ptr;
}

void search_deinit(UDF_INIT* initid){
    delete[] initid->ptr;
    sgx_destroy_enclave(eid);
}

