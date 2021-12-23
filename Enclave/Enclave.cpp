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

#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <vector>
#include "../Include/user_types.h"

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */

using namespace std;

#define ENC_KEY_SIZE 16 // for AES128
#define BATCH_SIZE 10000

//change to malloc for tokens , run ulimit -s 65536 to set stack size to
//65536 KB in linux

// local variables inside Enclave
string KW;
//generate key for BF
string K_BF;

BloomFilter *myBloomFilter;

//存储每个单词的更新个数
unordered_map<string, int> ST;
//std::unordered_map<std::string, std::vector<std::string>> D;

//删除的id
vector<std::string> D;

//Enclave maintains the M_c
//(w,id)->计数
std::unordered_map<std::string, int> M_c;

std::string stateString;

string Enc(string key, string meg)
{
    //long long len = meg.length() + 1;
    //len += 16 - (len % 16);//将len 变为blocksize 的整数倍，blokcsize为16

    //AES aes;
    //char* temp = new char[len + 1];
    //aes.MakeKey(key.c_str(), temp);

    //char* ans = new char[len + 1];
    //aes.Encrypt(meg.c_str(), ans, len);
    //delete[] temp;

    //return base64_encode((uint8_t*)ans, len);

    string strSrc = meg;
    const char *g_key = key.c_str();
    const char g_iv[17] = "gfdertfghjkuyrtg";
    if (strSrc.empty())
    {
        return NULL;
    }
    size_t length = strSrc.length();
    int block_num = length / BLOCK_SIZE + 1;
    //明文
    char *szDataIn = new char[block_num * BLOCK_SIZE + 1];
    memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
    memcpy(szDataIn, strSrc.c_str(), strSrc.length());
    //进行PKCS7Padding填充。
    int k = length % BLOCK_SIZE;
    int j = length / BLOCK_SIZE;
    int padding = BLOCK_SIZE - k;
    for (int i = 0; i < padding; i++)
    {
        szDataIn[j * BLOCK_SIZE + k + i] = padding;
    }
    szDataIn[block_num * BLOCK_SIZE] = '\0';
    //加密后的密文
    char *szDataOut = new char[block_num * BLOCK_SIZE + 1];
    memset(szDataOut, 0, block_num * BLOCK_SIZE + 1);
    //进行进行AES的CBC模式加密
    AES aes;
    aes.MakeKey(g_key, g_iv, 16, 16);
    aes.Encrypt(szDataIn, szDataOut, block_num * BLOCK_SIZE, AES::CBC);
    string str = base64_encode((unsigned char *)szDataOut,
                               block_num * BLOCK_SIZE);
    delete[] szDataIn;
    delete[] szDataOut;
    return str;
}

string H(string keyDel, string strdel)
{
    unsigned char tmplabeldel[SHA256_DIGESTLEN] = {0};
    compute_hmac_ex(tmplabeldel, (const uint8_t *)keyDel.c_str(), keyDel.length(), (const uint8_t *)strdel.c_str(),
                    strdel.length());
    string slabeldel = base64_encode((unsigned char *)tmplabeldel, 16);
    return slabeldel;
}

//按照空格分割
vector<string> splitBy(string str, char c)
{
    vector<string> ans;
    string temp;
    for (int i = 0; i < str.length(); i++)
    {
        if (str[i] == c)
        {
            ans.push_back(temp);
            temp = "";
        }
        else
            temp += str[i];
    }
    if (temp.length() > 0)
    {
        ans.push_back(temp);
    }
    return ans;
}

/*** setup */
void ecall_init()
{
    //随机生成函数
    uint8_t _KW[ENC_KEY_SIZE];
    sgx_read_rand(_KW, ENC_KEY_SIZE);
    KW = (char *)_KW;
    uint8_t _K_BF[ENC_KEY_SIZE];
    sgx_read_rand(_K_BF, ENC_KEY_SIZE);
    K_BF = (char *)_K_BF;

    //change reserver for M_C
    //uint64_t vector_size = 315000000;//hold up 15 mil k,v // about 40MB
    //uint64_t vector_size = 460000000;//hold up 22 mil k,v // about 55MB
    //uint64_t vector_size = 830000000;//hold up 40 mil k,v // about 110MB

    uint64_t vector_size = 20;

    uint8_t numHashs = 5;
    myBloomFilter = new BloomFilter(vector_size, numHashs);

    //reset M_c
    M_c.clear();
    //M_c.reserve(22000000);
}

void ecall_add(char *id_data, char *valuesPointer)
{
    string id = id_data;
    string attribute = valuesPointer;

    std::string k_w = H(KW, attribute);

    int c = 0;
    unordered_map<string, int>::iterator got = ST.find(attribute);
    if (got == ST.end())
    {
        c = 0;
    }
    else
    {
        c = got->second;
    }
    c++;

    ST[attribute] = c;

    string c_str = to_string(c);
    string k_id = H(k_w, c_str);

    string u = H(k_w, c_str);
    string v = Enc(k_id, id);

    DataStruct* u_arr = new DataStruct[1];
    DataStruct* v_arr = new DataStruct[1];

    memcpy(u_arr[0].content, u.c_str(), u.length() + 1);
    memcpy(v_arr[0].content, v.c_str(), v.length() + 1);

    string c_key = H(k_w, id);
    M_c[c_key] = c;

    string k_bf = k_w + id;
    myBloomFilter->add(H(K_BF, k_bf));

    ocall_add(u_arr, v_arr, 1, sizeof(DataStruct));
}

void ecall_del(char *id_str)
{
    string id = id_str;
    D.push_back(id);

    int random_len = 6;
    DataStruct *u_arr = new DataStruct[random_len];
    DataStruct *v_arr = new DataStruct[random_len];

    for (int i = 0; i < random_len; i++)
    {

        sgx_read_rand((uint8_t *)u_arr[i].content, RAND_LEN);
        sgx_read_rand((uint8_t *)v_arr[i].content, RAND_LEN);
    }
    ocall_add(u_arr, v_arr, random_len, sizeof(DataStruct));

    delete[] u_arr;
    delete[] v_arr;
}

void ecall_search(char *word)
{
    string keyword = word;

    if (ST.count(keyword) == 0)
        return;

    int c = ST[keyword];

    string k_w = H(KW, word);

    vector<int> st_w_c;
    for (int i = 1; i <= c; i++)
    {
        st_w_c.push_back(i);
    }

    vector<int> st_w_c_difference;

    for (string del_id : D)
    {
        string k_bf = k_w + del_id;
        string m_prime = H(K_BF, k_bf);

        if (myBloomFilter->possiblyContains(m_prime))
        {
            string c_key = H(k_w, del_id);
            st_w_c_difference.push_back(M_c[c_key]);
        }
    }

    vector<int> merged_st;
    set_difference(st_w_c.begin(), st_w_c.end(),
                   st_w_c_difference.begin(), st_w_c_difference.end(),
                   std::back_inserter(merged_st));

    size_t pair_no = merged_st.size();

    int batch = pair_no / BATCH_SIZE;

    for (int i = 0; i <= batch; i++)
    {

        int limit = BATCH_SIZE * (i + 1) > pair_no ? pair_no : BATCH_SIZE * (i + 1);
        int length = BATCH_SIZE * (i + 1) > pair_no ? pair_no - BATCH_SIZE * i : BATCH_SIZE;

        // printf("batch=%d limit=%d length=%d",batch,limit,length);

        DataStruct *Q_w_u_arr = new DataStruct[length];
        DataStruct *Q_w_id_arr = new DataStruct[length];

        for (int j = BATCH_SIZE * i; j < limit; j++)
        {
            string c_str = to_string(merged_st[j]);

            string u = H(k_w, c_str);

            memcpy(Q_w_u_arr[j - BATCH_SIZE * i].content, u.c_str(), u.length() + 1);

            string k_id = H(k_w, c_str);
            memcpy(Q_w_id_arr[j - BATCH_SIZE * i].content, k_id.c_str(), k_id.length() + 1);
        }
        ocall_search(Q_w_u_arr, Q_w_id_arr, length, sizeof(DataStruct));

        // delete[] Q_w_id_arr;
        // delete[] Q_w_id_arr;
    }
}

uint32_t get_sealed_data_size(const char *encrypt_data)
{
    return sgx_calc_sealed_data_size(0, (uint32_t)strlen(encrypt_data));
}

sgx_status_t seal_data(uint8_t *sealed_blob, uint32_t data_size, const char *encrypt_data)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, (uint32_t)strlen(encrypt_data));
    if (sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (sealed_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if (temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    //    printf("stateString %s\n",encrypt_data);
    sgx_status_t err = sgx_seal_data(0, (uint8_t *)"",
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

uint32_t get_sealed_state_size()
{
    stateString = "";
    const std::string splitChar = "|";

    //bloomFilter
    stateString += myBloomFilter->toString();
    stateString += splitChar;

    //ST
    for (auto i = ST.begin(); i != ST.end(); i++)
    {
        stateString += i->first + ":" + to_string(i->second) + ";";
    }
    stateString += splitChar;

    //M_c;
    for (auto i = M_c.begin(); i != M_c.end(); i++)
    {
        stateString += i->first + ":" + to_string(i->second) + ";";
    }
    stateString += splitChar;

    //key
    stateString += KW + splitChar + K_BF + splitChar;

    //del
    for (std::string s : D)
    {
        stateString += s + ";";
    }
    stateString += splitChar;

    return get_sealed_data_size(stateString.c_str());
}

void parseStat(std::string str)
{
    //    printf("%s\n",str.c_str());
    std::vector<std::string> list = splitBy(str, '|');

    //    printf("parse number %d\n", list.size());

    myBloomFilter->parse_string(list[0]);

    //ST
    std::vector<std::string> ST_list = splitBy(list[1], ';');
    for (int i = 0; i < ST_list.size(); i++)
    {
        std::vector<std::string> temp = splitBy(ST_list[i], ':');
        ST[temp[0]] = stoi(temp[1]);

        //        printf("ST %s %s\n",temp[0].c_str(),temp[1].c_str());
    }

    //M_c
    std::vector<std::string> Mc_list = splitBy(list[2], ';');
    for (int i = 0; i < Mc_list.size(); i++)
    {
        std::vector<std::string> temp = splitBy(Mc_list[i], ':');
        M_c[temp[0]] = stoi(temp[1]);
        //        printf("M_c %s %s\n",temp[0].c_str(),temp[1].c_str());
    }

    KW = list[3];

    K_BF = list[4];

    //    printf("KW %s\n",KW);
    //    printf("K_BF %s\n",K_BF);

    //D
    D = splitBy(list[5], ';');
}

sgx_status_t get_sealed_state(uint8_t *out, uint32_t sealed_size)
{
    return seal_data(out, sealed_size, stateString.c_str());
}

sgx_status_t unseal_data(const uint8_t *sealed_blob, size_t data_size, char *out)
{

    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);

    if (decrypt_data_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (decrypt_data_len > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *decrypt_data = (uint8_t *)malloc(data_size);
    memset(decrypt_data, 0x00, data_size);

    if (decrypt_data == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    uint32_t size = (uint32_t)data_size;
    sgx_status_t ret = sgx_unseal_data(
        (const sgx_sealed_data_t *)sealed_blob,
        (uint8_t *)"", 0,
        decrypt_data,
        &size);


    if (ret != SGX_SUCCESS)
    {
        free(decrypt_data);
        return ret;
    }
    //    parseStat((char *) decrypt_data);
    memcpy(out, decrypt_data, data_size);
    free(decrypt_data);

    return SGX_SUCCESS;
}

sgx_status_t ecall_unseal_state(const uint8_t *sealed_blob, size_t data_size)
{
    char *out = new char[data_size];
    sgx_status_t ret = unseal_data(sealed_blob, data_size, out);
    if (ret != SGX_SUCCESS)
    {
        delete[] out;
        return ret;
    }
    parseStat(out);
    delete[] out;
    return SGX_SUCCESS;
}

void free_all()
{
    delete myBloomFilter;
}

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}