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
#include "Enclave.h"
#include "Enclave_t.h" 
#include <stdarg.h>
#include "hash.h"
#include "Base64.h"
#include <algorithm>
#include "util.h"
using namespace std;

string keyInd = "";
struct myaeskey aesk;



char ststr[3000] = {0};



char delSet[100] = {0};

char delstr[150000] = {0};


void ecall_test(size_t in, size_t *out)
{
    *out = in * 10086 + 10000;
}


char* printf(const char *fmt, ...) 
{
    
    int n, size = 100;
    char *p;
    va_list ap;
    if ( (p = (char *) malloc(size*sizeof(char))) == NULL)
        return 0;
    while (1) 
    {
        
        va_start(ap, fmt);
        n = vsnprintf (p, size, fmt, ap);
        va_end(ap);
        
        if (n > -1 && n < size){
            ocall_print_string(p);
            return NULL;
        }
        
        size *= 2; 
        if ((p = (char *)realloc(p, size*sizeof(char))) == NULL)
            return NULL;
    }
}


uint32_t get_sealed_data_size(char *encrypt_data)
{
    return sgx_calc_sealed_data_size(0, (uint32_t)strlen(encrypt_data));
}

sgx_status_t seal_data(uint8_t* sealed_blob, uint32_t data_size, char *encrypt_data)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, (uint32_t)strlen(encrypt_data));
    if (sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (sealed_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    sgx_status_t  err = sgx_seal_data(0, (uint8_t *)"", 
                        (uint32_t)strlen(encrypt_data), 
                        (uint8_t *)encrypt_data, 
                        sealed_data_size, 
                        (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS)
    {
        // Copy the sealed data to outside buffer
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }
    free(temp_sealed_buf);
    return err;
}



void compute_hmac_ex(unsigned char* dest, const uint8_t *key, uint32_t klen, const uint8_t *msg, uint32_t mlen)
{
	uint8_t md[SHA256_DIGESTLEN] = {0};
	HMAC_SHA256_CTX hmac;
	hmac_sha256_init(&hmac, key, klen);
	hmac_sha256_update(&hmac, msg, mlen);
	hmac_sha256_final(&hmac, md);
	memcpy(dest, md, SHA256_DIGESTLEN);
}

sgx_status_t unseal_state(const uint8_t *sealed_blob, size_t data_size)
{
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    if (decrypt_data_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if(decrypt_data_len > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *decrypt_data = (uint8_t *)malloc(data_size);
    memset(decrypt_data, 0x00, data_size);

    if(decrypt_data == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    uint32_t size = (uint32_t) data_size;
    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, (uint8_t *)"", 0, decrypt_data, &size);
    if (ret != SGX_SUCCESS)
    {
        free(decrypt_data);
        return ret;
    }
    
    memset(ststr, 0, strlen(ststr));
    memcpy(ststr, (const char *)decrypt_data, strlen((const char *)decrypt_data));
    
    return SGX_SUCCESS;    
}

sgx_status_t unseal_dellist(const uint8_t *sealed_blob, size_t data_size)
{
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    if (decrypt_data_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if(decrypt_data_len > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *decrypt_data = (uint8_t *)malloc(data_size);
    memset(decrypt_data, 0x00, data_size);

    if(decrypt_data == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    uint32_t size = (uint32_t) data_size;
    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, (uint8_t *)"", 0, decrypt_data, &size);
    if (ret != SGX_SUCCESS)
    {
        free(decrypt_data);
        return ret;
    }
    
    memset(delstr, 0, sizeof(delstr));
    memcpy(delstr, (char *)decrypt_data, strlen((char *)decrypt_data));
    
    return SGX_SUCCESS;
}






sgx_status_t parsekey(){
    int i,j;
    char *skey = new char[100];
    for(i = 0; ststr[i] != '\0' && ststr[i] != '*'; i++){
        skey[i] = ststr[i];
    }
    skey[i++] = '\0';
    char *iv = new char[100];
    for(j = 0; ststr[i] != '\0' && ststr[i] != '*'; i++){
        iv[j++] = ststr[i];
    }
    iv[j] = '\0';
    aesk.skey = skey;
    aesk.iv = iv;
    return SGX_SUCCESS;
}

sgx_status_t parsestate(char *keyword, mystate &myst){
    
    string Srcstr(ststr);
    string word(keyword);
    char *ge = "|";
    if (Srcstr.find(word) == -1){       
        myst.setKeyWord(keyword, strlen(keyword));
        myst.setCnt(0);
        myst.setDel(0);
    } else {
        char geword[100] = {0};
        memcpy(geword, ge, strlen(ge));
        memcpy(geword + strlen(ge), word.c_str(), word.length());
        string sgeword(geword);
        int start = Srcstr.find(sgeword);
        int end = Srcstr.find(ge, start + 1);
        char tmp[end - (start +1) + 2] = {0};
        memcpy(tmp, Srcstr.c_str() + start + 1, end-(start + 1) + 1);
        Srcstr.erase(start + 1, strlen(tmp));

        string stmp(tmp);
        string sign = "*";
        int wend=stmp.find(sign,0);
        myst.setKeyWord(stmp, wend);

        int cend = stmp.find(sign, wend + 1);
        char scnt[cend - wend + 1] = {0};
        memset(scnt, 0, strlen(scnt));
        memcpy(scnt, tmp + wend + 1, cend - wend - 1);
        string sscnt(scnt);
        int cnt = atoi(sscnt.c_str());
        myst.setCnt(cnt);

        int dend = stmp.find(ge, cend + 1);
        char sdel[dend - cend + 1];
        memset(sdel, 0, strlen(sdel) + 1);
        memcpy(sdel, tmp + cend + 1, dend - cend - 1);
        
        string ssdel(sdel);
        int del = atoi(ssdel.c_str());
        myst.setDel(del);
        
       
        memset(ststr, 0, strlen(ststr) + 1);
        memcpy(ststr, Srcstr.c_str(), Srcstr.length());
    }
    return SGX_SUCCESS;
}

sgx_status_t parsedellist(char *blockDel){
    string del = delstr;
    memset(blockDel, 0, strlen(blockDel)); 
    memcpy(blockDel, delstr, 68);
    del.erase(0, 68);
    

    memset(delstr, 0, sizeof(delstr));
    memcpy(delstr, del.c_str(), del.length());
    
    return SGX_SUCCESS;
}


uint32_t get_sealed_state_size(){
    return sgx_calc_sealed_data_size(0, (uint32_t)strlen(ststr));
}

sgx_status_t seal_state(uint8_t* sealed_blob, uint32_t data_size)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, (uint32_t)strlen(ststr));
    
    if (sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (sealed_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    memset(temp_sealed_buf, 0, sealed_data_size);
    if(temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    sgx_status_t  err = sgx_seal_data(0, (uint8_t *)"", 
                        (uint32_t)strlen(ststr), 
                        (uint8_t *)ststr, 
                        sealed_data_size, 
                        (sgx_sealed_data_t *)temp_sealed_buf);
    
    if (err == SGX_SUCCESS)
    {
        // Copy the sealed data to outside buffer
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }
    free(temp_sealed_buf);
    return err;
}

uint32_t get_sealed_dellist_size(){
    
    return sgx_calc_sealed_data_size(0, (uint32_t)strlen(delstr));
}



sgx_status_t seal_DList(uint8_t* sealed_blob, uint32_t data_size){
    
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, (uint32_t)strlen(delstr));
    if (sealed_data_size == UINT32_MAX){
        return SGX_ERROR_UNEXPECTED;
    }
        
    if (sealed_data_size > data_size){
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    memset(temp_sealed_buf, 0, sealed_data_size);
    if(temp_sealed_buf == NULL){
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    sgx_status_t  err = sgx_seal_data(0, (uint8_t *)"", 
                        (uint32_t)strlen(delstr), 
                        (uint8_t *)delstr, 
                        sealed_data_size, 
                        (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS)
    {
        // Copy the sealed data to outside buffer
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }
    free(temp_sealed_buf);
    return err;  
}


void uptst(mystate &myst){
    
    char *newst = new char[125];
    memset(newst, 0, 125);
    char *star = "*";
    char *ge = "|\n";
    
    memcpy(newst, myst.keyword, strlen(myst.keyword));
    memcpy(newst + strlen(myst.keyword), star, 1);
    memcpy(newst + strlen(myst.keyword) + 1, 
            to_string(myst.cnt).c_str(), 
            strlen(to_string(myst.cnt).c_str()));
    memcpy(newst + strlen(myst.keyword) + 1 + strlen(to_string(myst.cnt).c_str()),
            star, 1);
    memcpy(newst + strlen(myst.keyword) + 1 + strlen(to_string(myst.cnt).c_str()) + 1, 
            to_string(myst.del).c_str(), 
            strlen(to_string(myst.del).c_str()));
    memcpy(newst + strlen(myst.keyword) + 1 + strlen(to_string(myst.cnt).c_str()) + 1 + strlen(to_string(myst.del).c_str()),
            ge, 1);
    
    memcpy(ststr + strlen(ststr), newst, strlen(newst));
    delete[] newst;
}
void cntInc(mystate &myst){
    int newcnt = myst.cnt + 1;
    myst.setCnt(newcnt);
    uptst(myst);
}

void delInc(mystate &myst){
    int newdel = myst.del + 1;
    myst.setDel(newdel);
    uptst(myst);
}

int genLabelw(string keyw, char *kw, char *labelw){
    unsigned char tmplabelw[SHA256_DIGESTLEN] = {0};
    string skeyword(kw);
    compute_hmac_ex(tmplabelw, (const uint8_t *)keyw.c_str(), keyw.length(), (const uint8_t *) skeyword.c_str(), skeyword.length());
    string slabelw = base64_encode(tmplabelw, 16);
    memcpy(labelw, slabelw.c_str(), slabelw.length());

    return 0;
}


sgx_status_t insertidx(char *keyword, int keysize, int id, char *BlockInd, int ilengthInd, char *BlockW, int ilengthW){
    if (strlen(keyword) > keysize){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    mystate myst;
    parsestate(keyword, myst);
    

    
    string strid = to_string(id);
    keyInd = EncryptionAES((const char *)(aesk.skey), (const char *)(aesk.iv), strid);
    string sind = DecryptionAES((const char *)(aesk.skey), (const char *)(aesk.iv), keyInd);
    
    

    
    char *sign = "1";
    strncat(keyword, sign, 2);
    string strword(keyword);
    string keyw = EncryptionAES((const char *)aesk.skey, (const char *)aesk.iv, strword);
    
    
    
    
    unsigned char* tmplabelind = new unsigned char[SHA256_DIGESTLEN];
    memset(tmplabelind, 0, SHA256_DIGESTLEN);
    
    char* labelind = new char[25];
    memset(labelind, 0, 25);
	compute_hmac_ex(tmplabelind, (const uint8_t *)keyInd.c_str(), keyInd.length(), (const uint8_t *)strid.c_str(), strid.length());
    string slabelind = base64_encode(tmplabelind, 16);
    memcpy(labelind, slabelind.c_str(), slabelind.length());
    
    
    
    
    
    char* labelw = new char[25];
    memset(labelw, 0, 25);
    char *cnt = (char *)((to_string(myst.cnt)).c_str());
    char *kw = new char[strlen(myst.keyword) + strlen(cnt) + 1];
    memcpy(kw, myst.keyword, strlen(myst.keyword));
    memcpy(kw + strlen(myst.keyword), cnt, strlen(cnt));
    kw[strlen(cnt)+strlen(myst.keyword)] = '\0';
    genLabelw(keyw, kw, labelw);
    
    

    
    int length = 109;
    
    unsigned char* labelww = new unsigned char[length];
    memset(labelww, 0, 109);
    memcpy(labelww, labelw, strlen((char *)labelw));
    memcpy(labelww + strlen((char *)labelw), myst.keyword, strlen(myst.keyword));
    char *pad = "#123456789987654321123456789123456789123456789123456789123456789123456789123456789";
    memcpy(labelww + strlen((char *)labelw) + strlen(myst.keyword), pad, 108-strlen((char *)labelw)-strlen(myst.keyword));
    
    

    
    char idw[10] = {0};
    memcpy(idw, (char *)strid.c_str(), strlen((char *)strid.c_str()) + 1);
    string sidw(idw);
    
    unsigned char* tmplabeli = new unsigned char[33];
    memset(tmplabeli, 0, 33);
    
    unsigned char* labeli = new unsigned char[length];
    memset(labeli, 0, length);
    compute_hmac_ex(tmplabeli, (const uint8_t *)keyInd.c_str(), keyInd.length(), (const uint8_t *)idw, sidw.length());
    string slabeli = base64_encode(tmplabeli, 16);
    int roundi = 108/(slabeli.length());
    int ik;
    for(ik = 0 ; ik < roundi; ik ++){
        memcpy(labeli + ik * slabeli.length(), slabeli.c_str(), slabeli.length());
    }
    memcpy(labeli + ik * slabeli.length(), slabeli.c_str(), 108 - ik * slabeli.length());
    
    
    
    
    unsigned char* labelwStar = new unsigned char[length];
    memset(labelwStar, 0, length);
    int i;
    for(i = 0; i < length - 1; i++){
        labelwStar[i] = labelww[i] ^ labeli[i];
    }
    string slabelwStar = base64_encode((unsigned char*) labelwStar, 108);
    
    

    
    string res = EncryptionAES((const char*)keyw.c_str(), (const char *)aesk.iv, strid);
    

    
    
    int lengthInd = strlen(labelind) + length;      
    if (lengthInd > ilengthInd){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    memcpy(BlockInd, labelind, strlen(labelind));
    memcpy(BlockInd + strlen(labelind), (char *)(slabelwStar.c_str()), slabelwStar.length());
    BlockInd[strlen(labelind) + slabelwStar.length()] = '\0';
    

    
    int lengthW = strlen(labelw) + res.length();
    if(lengthW > ilengthW){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    memset(BlockW, 0, strlen(BlockW));
    memcpy(BlockW, labelw, strlen(labelw));
    memcpy(BlockW + strlen(labelw), res.c_str(), res.length());
    BlockW[ strlen(labelw) + res.length()] = '\0';
    

    
    cntInc(myst);
    
    
    delete[] tmplabelind;
    delete[] labelind;
    delete[] labelw;
    delete[] labelww;
    delete[] tmplabeli;
    delete[] labeli;
    delete[] labelwStar;
    return SGX_SUCCESS;
}

int genkeywdel(char *keyword, string& keyw, string& keyDel){
    char *signO = "1";
    char *signZ = "0";
    char keywordO[80] = {0};
    char keywordZ[80] = {0};
    memcpy(keywordO, keyword, strlen(keyword));
    memcpy(keywordZ, keyword, strlen(keyword));
    keywordO[strlen(keyword)] = '\0';
    keywordZ[strlen(keyword)] = '\0';
    strncat(keywordO, signO, 2);
    strncat(keywordZ, signZ, 2);
    string strwordO(keywordO);
    string strwordZ(keywordZ);
    keyw = EncryptionAES((const char *)aesk.skey, (const char *)aesk.iv, strwordO);
    keyDel = EncryptionAES((const char *)aesk.skey, (const char *)aesk.iv, strwordZ);

    return 0;
}

sgx_status_t genLabelInd(char *ind, int lencind, char *labelInd, int lenlabelInd){
    if(lencind > 10){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if(lenlabelInd > 24){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    string strid(ind);
    keyInd = EncryptionAES((const char *)(aesk.skey), (const char *)(aesk.iv), strid);
    
    
    unsigned char tmplabelind[SHA256_DIGESTLEN] = {0};
	compute_hmac_ex(tmplabelind, (const uint8_t *)keyInd.c_str(), keyInd.length(), (const uint8_t *)strid.c_str(), strid.length());
    string slabelind = base64_encode(tmplabelind, 16);
    memcpy(labelInd, slabelind.c_str(), slabelind.length());
    
    return SGX_SUCCESS;
}

int genH4(string strdel, char *labeldel, string keyDel){
    unsigned char tmplabeldel[SHA256_DIGESTLEN] = {0};
    compute_hmac_ex(tmplabeldel, (const uint8_t *)keyDel.c_str(), keyDel.length(), (const uint8_t *)strdel.c_str(), strdel.length());
    string slabeldel = base64_encode((unsigned char *)tmplabeldel, 16);
    memcpy(labeldel, slabeldel.c_str(), slabeldel.length());
    
    return 0;
}

sgx_status_t genlabelw(char *labelwStar, int lenStar, char *ind, int lencind, char *labelw, int lenw, char *BlockDel, int lenbdel, char *wdellabel, int wdellen){
    if (lenStar < 24){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (lencind > 10){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (lenw < 24){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (lenbdel < 64){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (wdellen < 24){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    int length = 109;
    
    char *idw = new char[10];
    memset(idw, 0, 10);
    
    memcpy(idw, ind, lencind);
    idw[strlen(ind)] = '\0';
    char labeli[length] = {0};

    string sidw(idw);
    
    unsigned char* tmplabeli = new unsigned char[33];
    memset(tmplabeli, 0, 33);
    memset(labeli, 0, length);
    compute_hmac_ex(tmplabeli, (const uint8_t *)keyInd.c_str(), keyInd.length(), (const uint8_t *)idw, sidw.length());
    
    
    string slabeli = base64_encode(tmplabeli, 16);
    int roundi = 108/(slabeli.length());
    int ik;
    for(ik = 0 ; ik < roundi; ik ++){
        memcpy(labeli + ik * slabeli.length(), slabeli.c_str(), slabeli.length());
    }
    memcpy(labeli + ik * slabeli.length(), slabeli.c_str(), 108 - ik * slabeli.length());
    
    
    char *labelww = new char[109];
    memset(labelww, 0, 109);
    int i;
    int  cnt = 0;
    string slabelwStar64 = labelwStar;
    string slabelwStar = base64_decode(slabelwStar64);

    for (i = 0 ; i < length-1; i ++){
        labelww[i] = (slabelwStar.c_str())[i] ^ labeli[i];
    }
    labelww[i] = '\0';
    memset(labelw, 0, sizeof(labelw));
    memcpy(labelw, labelww, 24);       
    labelw[24] = '\0';
    string slabelww = labelww;
    
    
    string sign = "#";
    int j = slabelww.find(sign, 25);
    
    char* keyword = new char[80];
    memset(keyword, 0, sizeof(keyword));
    memcpy(keyword, labelww + 24, j - 24);
    keyword[j - 24] = '\0';
    
    
    string keyw = "";
    string keyDel = "";
    genkeywdel(keyword, keyw, keyDel);

    
    mystate myst;
    parsestate(keyword, myst);
    
    
    char *labeldel = new char[25];
    memset(labeldel, 0, 25);
    
    char* blockDel = new char[72];
    memset(blockDel, 0, 72);
    int didx = strlen(delstr)/68;
    if (myst.cnt - myst.del >= 2){      
        
        
        string strdel = to_string(myst.del);
        
        
	    genH4(strdel, labeldel, keyDel);
        
        
        string slabelw = labelw;
        string labelwDel = EncryptionAES((const char*)keyw.c_str(), (const char *)aesk.iv, slabelw);

        
        
        memcpy(blockDel, labeldel, 24);
        memcpy(blockDel + strlen(blockDel), labelwDel.c_str(), labelwDel.length());
        
        
        if (didx > 0){
            
        } else {
            memset(delstr, 0, sizeof(delstr));
        }
        
        memcpy(delstr + strlen(delstr), blockDel, strlen(blockDel));
        
        didx += 1;
        
        
        if (didx < 200){      
            delInc(myst);
            
            
        } else {            
            parsedellist(BlockDel);
            delInc(myst);
            
        }
        
        
    } else if (myst.cnt > 1){
        
        memset(wdellabel, 0, strlen(wdellabel));
        for(int i = 0; i < myst.del; i++){
            genH4(to_string(i), labeldel, keyDel);
            string sdel = delstr;
            int wdelStart = sdel.find(labeldel);
            
            if (didx > 0){
                if (wdelStart != -1){
                
                    cnt++;
                    didx -= 1;
                    sdel.erase(wdelStart, 60);
                    

                    memset(delstr, 0, sizeof(delstr));
                    memcpy(delstr, sdel.c_str(), sdel.length());
                    
                } else{
                    cnt++;
                    memcpy(wdellabel + strlen(wdellabel), labeldel, 24);
                }
            }
        }
    }
    
    ocall_insertidx_err(labelw);
    delete[] idw;
    delete[] tmplabeli;
    delete[] labelww;
    delete[] keyword;
    delete[] labeldel;
    delete[] blockDel;
    
    
    return SGX_SUCCESS;
}

sgx_status_t genLabeldel(char* keyword, int lenword, char *strdel, int lendel){
    if (lenword < 0){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (lendel < 0){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    string keyw = "";
    string keyDel = "";
    char *sign = "*";
    genkeywdel(keyword, keyw, keyDel);

    mystate myst;

    parsestate(keyword, myst);
    
    char labeldel[25] = {0};
    for(int i = 0 ; i < myst.del; i++){
        memset(labeldel, 0, strlen(labeldel));
        genH4(to_string(i), labeldel, keyDel);
        string sdel = labeldel;
        string sdelstr = delstr;
        int start = sdelstr.find(sdel);
        if (start != -1){
            int end = sdelstr.find("*", start + 1);
            
            for (int i = 0 ; i < end - start -23; i++){
                delSet[strlen(delSet) + i] = delstr[start + 24 + i];
            }
        } else {
            
            for (int i = 0 ; i < sdel.length(); i++){
                strdel[strlen(strdel) + i] = labeldel[i];
            }
        }
    }
    uptst(myst);
    return SGX_SUCCESS;
}

sgx_status_t GetLabelRes(char *keyword, int lenword, char *labelSetOut, int lenOut, char *labelRes, int lenlres){
    if(lenword > 100){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if(lenOut >160000){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if(lenlres < 0){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    mystate myst;
    parsestate(keyword, myst);

    char *sign = "1";
    char *star = "*";
    string sstar = star;
    strncat(keyword, sign, 2);
    string strword(keyword);//w||1
    string keyw = EncryptionAES((const char *)aesk.skey, (const char *)aesk.iv, strword);
    
    int i;
    char labelw[25] = {0};
    string slabelSetout = labelSetOut;
    string sdelstr = delstr;
    
    for(i = 0 ; i <= myst.cnt; i++){
        string sind = to_string(i);
        int len = strlen(myst.keyword) + sind.length() + 1;
        char kw[len] = {0};
        memcpy(kw, myst.keyword, strlen(myst.keyword));
        
        for (int i = 0 ; i < sind.length(); i++){
            kw[strlen(myst.keyword) + i] = (sind.c_str())[i];
        }
        genLabelw(keyw, kw, labelw);
        string slabelw = labelw;
        string ctlabelw = EncryptionAES((const char *)keyw.c_str(), (const char *)aesk.iv, slabelw);
        if (slabelSetout.find(ctlabelw) != -1 || sdelstr.find(ctlabelw) != -1) {
            
        } else {
            memcpy(labelRes + strlen(labelRes), labelw, strlen(labelw));
            
        }
        
    }
    
    uptst(myst);
    return SGX_SUCCESS;
}

sgx_status_t getInd(char *keyword, int lenword, char *res, int len, char *ids, int idlen){
    if (lenword >100){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (len < 16){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (idlen < 0){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    char *sign = "1";
    strncat(keyword, sign, 2);
    string strword(keyword);
    string keyw = EncryptionAES((const char *)aesk.skey, (const char *)aesk.iv, strword);

    string sres = res;
    int start, end;
    start = 0;
    end = sres.find("**");
    
    
    char *ct = new char[64];
    memset(ct, 0, 64);
    memset(ids, 0, strlen(ids));
    while(end != -1){
        memcpy(ct, res + start, end - start);
        string sct = ct;
        string pt = DecryptionAES((const char *)keyw.c_str(), (const char *)aesk.iv, sct);

        start = end + 2;
        end = sres.find("**", end + 1);
        memcpy(ids + strlen(ids), pt.c_str(), pt.length());
        memcpy(ids + strlen(ids), "*", 1);
    }
    delete[] ct;
    return SGX_SUCCESS;
}
