//
// Created by asunalxh on 2021/10/23.
//

#include "Util.h"

#include <string.h>
#include <iostream>
#include "AES.h"
#include "Base64.h"

string Enc(string key, string meg) {
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
    if (strSrc.empty()) {
        return NULL;
    }
    size_t length = strSrc.length();
    int block_num = length / BLOCK_SIZE + 1;
    //明文
    char *szDataIn = new char[block_num * BLOCK_SIZE + 1];
    memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
    strcpy(szDataIn, strSrc.c_str());
    //进行PKCS7Padding填充。
    int k = length % BLOCK_SIZE;
    int j = length / BLOCK_SIZE;
    int padding = BLOCK_SIZE - k;
    for (int i = 0; i < padding; i++) {
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
    string str = base64_encode((unsigned char *) szDataOut,
                               block_num * BLOCK_SIZE);
    delete[] szDataIn;
    delete[] szDataOut;
    return str;
}

string Dec(string key, string meg) {
    //AES aes;
    //char* temp = new char[meg.length() + 1];
    //aes.MakeKey(key.c_str(), temp);
    //char* ans = new char[meg.length() + 1];

    //string decode_msg = base64_decode(meg);
    //aes.Decrypt(decode_msg.c_str(), ans, decode_msg.length());
    //delete[] temp;
    //return ans;

    string strSrc = meg;
    char *g_key = new char[key.length() + 1];
    memcpy(g_key,key.c_str(),key.length());
    const char g_iv[17] = "gfdertfghjkuyrtg";
    string strData = base64_decode(strSrc);
    size_t length = strData.length();
    //密文
    char *szDataIn = new char[length + 1];
    memcpy(szDataIn, strData.c_str(), length + 1);
    //明文
    char *szDataOut = new char[length + 1];
    memcpy(szDataOut, strData.c_str(), length + 1);
    //进行AES的CBC模式解密
    AES aes;
    aes.MakeKey(g_key, g_iv, 16, 16);
    aes.Decrypt(szDataIn, szDataOut, length, AES::CBC);
    //去PKCS7Padding填充
    if (0x00 < szDataOut[length - 1] <= 0x16) {
        int tmp = szDataOut[length - 1];
        for (int i = length - 1; i >= length - tmp; i--) {
            if (szDataOut[i] != tmp) {
                memset(szDataOut, 0, length);
                cout << "去填充失败！解密出错！！" << endl;
                break;
            } else
                szDataOut[i] = 0;
        }
    }
    char *res = new char[length + 1];
    int i;
    for (i = 0; szDataOut[i] != '$' && szDataOut[i] != '\0'; i++) {
        res[i] = szDataOut[i];
    }
    res[i] = '\0';
    string strDest(res);
    delete[] szDataIn;
    delete[] szDataOut;
    delete[] res;
    return strDest;
}

//随机加密
string RndPt(const string &pt) {
    size_t length = pt.length();
    char *cpt = new char[length + 10];
    memcpy(cpt, pt.c_str(), length + 1);
    int rnd = rand() % 1000 + 1;
    string ssrnd = to_string(rnd);
    size_t slength = ssrnd.length();
    char *crnd = new char[length + 10];
    memcpy(crnd, ssrnd.c_str(), length + 1);
    char sign[2] = "$";
    strcat(cpt, sign);
    strcat(cpt, crnd);
    string res(cpt);
    delete[] cpt;
    delete[] crnd;
    return res;
}

//按照空格分割
vector<string> splitBySpace(string str) {
    vector<string> ans;
    string temp;
    for (int i = 0; i < str.length(); i++) {
        if (str[i] == ' ') {
            if (temp.length() > 0) {
                ans.push_back(temp);
                temp = "";
            }
        } else
            temp += str[i];
    }
    if (temp.length() > 0) {
        ans.push_back(temp);
    }
    return ans;
}