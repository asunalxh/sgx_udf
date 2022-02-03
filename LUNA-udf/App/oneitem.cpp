#pragma once
#include "oneitem.h"
#include "Base64.h"

using namespace std;

string parseInd(int ind)
{
    int i = 1, k = 0;
    char *tmp = (char*) malloc(10);
    while(ind) 
    {
        i = ind % 10;
        ind = ind / 10;
        if (i != 0)
        {
            tmp[k++] = (char)(i + '0');
        }
    }
    tmp[k] = '\0';
    char *cind = (char*) malloc(10); 
    int j;
    for (j = 0; j < k; j ++)
    {
        cind[j] = tmp[k-j-1];
    }
    cind[j] = '\0';
    string str(cind);
    free(tmp);
    free(cind);
    return str;
}
string RndPt(const string& pt){
    size_t length = pt.length();
    char *cpt = new char[length + 10];
    memcpy(cpt, pt.c_str(), length + 1);
    int rnd = rand()%1000 +1;
    string ssrnd = parseInd(rnd);
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
bool GetValue(dblp* item, int ind)
{
    ifstream fin("/home/lvsiyi/dataset/tpch-csv/PART.csv", ios::in); //打开文件流操作
    fin.seekg(18 * (ind-1));
    if (!fin){
        return false;
    }
    string line;
    getline(fin, line);
    istringstream sin(line); //将整行字符串line读入到字符串流istringstream中 
    //vector<string> fields; //声明一个字符串向量
    string field;
    getline(sin, field, ','); //将字符串流sin中的字符读入到field字符串中，以逗号为分隔符
    getline(sin, field, ' ');

    item->journal = field; //清除掉向量fields中第二个元素的无效字符，并赋值给变量age
    item->journal = "######";
    fin.close();
    
    return true;


    /*std::ifstream ifs;
    ifs.open("/home/lvsiyi/dataset/tpch-csv/PART.csv", std::ios::in);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file " << std::endl;
        return false;
    }
    if (!ifs.is_open())
        return false;
    string line;
    getline(ifs, line);
    if (ifs.fail())
    {
        std::cout << "Failed to read the file" << std::endl;
        return false;
    }
    ifs.close();
    int pos = line.find(",");
    char tmp[100] = {0};
    memcpy(tmp, (line.c_str()) + pos + 1, strlen(line.c_str()) - pos - 1);
    item.journal = tmp;
    return true;*/
}

bool deletebyInd(char *tabname, int ind)
{
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;
    
    char *server = "localhost";
    char *user = "root";
    char *password = "root1234";
    //char *database = "dblp";
    char *database = "tpch";
    char query[100] = "delete ";
    char *subqry0 = " from ";
    strcat(query, subqry0);
    strcat(query, tabname);
    char *subqry1 = " where id = ";
    strcat(query, subqry1);
    string str = to_string(ind);
    char *cstr = (char *)str.c_str();
    strcat(query, cstr);
    conn = mysql_init(NULL);

    /*connect to MySQL*/
    if (!mysql_real_connect(conn, server, user, password, database, 0, NULL, 0))
    {
        fprintf(stderr, "%s/n", mysql_error(conn));
    }
    /*Send SQL Query*/
    char *set_wait = "set global wait_timeout = 2880000";
    mysql_query(conn, set_wait);
    char *set_int = "set global interactive_timeout = 2880000";
    mysql_query(conn, set_int);
    if (mysql_query(conn, query))
    {
        fprintf(stderr, "%s/n", mysql_error(conn));
    }
    res = mysql_store_result(conn);
    
    /*close connection*/
    mysql_free_result(res);
    mysql_close(conn);
    return true;
}


string EncryptionAES(const string& strSrc) //AES加密
{
    const char g_key[17] = "asdfwetyhjuytrfd";
    const char g_iv[17] = "gfdertfghjkuyrtg";
    if (strSrc.empty()){
        return NULL;
    }
    size_t length = strSrc.length();
    int block_num = length / BLOCK_SIZE + 1;
    //明文
    char* szDataIn = new char[block_num * BLOCK_SIZE + 1];
    memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
    strcpy(szDataIn, strSrc.c_str());
 
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
    string str = base64_encode((unsigned char*) szDataOut,
            block_num * BLOCK_SIZE);
    delete[] szDataIn;
    delete[] szDataOut;
    return str;
}
string DecryptionAES(const string& strSrc) //AES解密
{
    const char g_key[17] = "asdfwetyhjuytrfd";
    const char g_iv[17] = "gfdertfghjkuyrtg";
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
                cout << "去填充失败！解密出错！！" << endl;
                break;
            }
            else
                szDataOut[i] = 0;
        }
    }
    char *res = new char[length + 1];
    int i;
    for(i = 0; szDataOut[i] != '$' && szDataOut[i] != '\0'; i++)
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
