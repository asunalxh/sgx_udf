#pragma once
#include "util.h"
#include "Base64.h"
using namespace std;

string EncryptionAES(const char* g_key, const char* g_iv, const string& strSrc) //AES加密
{
    if (strSrc.empty()){
        return NULL;
    }
    size_t length = strSrc.length();
    int block_num = length / BLOCK_SIZE + 1;
    //明文
    char* szDataIn = new char[block_num * BLOCK_SIZE + 1];
    memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
    memcpy(szDataIn, strSrc.c_str(), block_num * BLOCK_SIZE + 1);

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
    memset(szDataOut, 0x00, block_num * BLOCK_SIZE + 1);
 
    //进行进行AES的CBC模式加密
    AES aes;
    aes.MakeKey(g_key, g_iv, 16, 16);
    aes.Encrypt(szDataIn, szDataOut, block_num * BLOCK_SIZE, AES::CBC);
    
    string str = base64_encode((unsigned char*) szDataOut,
            block_num * BLOCK_SIZE);
    
    delete[] szDataIn;
    delete[] szDataOut;
    return str;
}
string DecryptionAES(const char* g_key, const char* g_iv, const string& strSrc) //AES解密
{

    string strData = base64_decode(strSrc);
    
    size_t length = strData.length();
    //密文
    char *szDataIn = new char[length + 1];
    memcpy(szDataIn, strData.c_str(), length+1);
    
    //明文
    char *szDataOut = new char[length + 1];
    memcpy(szDataOut, strData.c_str(), length+1);
 
    //进行AES的CBC模式解密
    AES aes;
    aes.MakeKey(g_key, g_iv, 16, 16);
    
    aes.Decrypt(szDataIn, szDataOut, length, AES::CBC);
    
    //去PKCS7Padding填充
    if (0x00 < szDataOut[length - 1] <= 0x16)
    {
        int tmp = szDataOut[length - 1];
        for (int i = length - 1; i >= length - tmp; i--)
        {
            if (szDataOut[i] != tmp)
            {
                memset(szDataOut, 0, length);
                
                break;
            }
            else
                szDataOut[i] = 0;
        }
    }
    char *res = new char[length + 1];
    int i;
    for(i = 0; szDataOut[i] != '\0'; i++)
    {
        res[i] = szDataOut[i];
    }
    res[i] = '\0';
    
    
    
    string strDest(res);
    delete[] szDataIn;
    delete[] szDataOut;
    delete[] res;
    return strDest;
}
