//
// Created by asunalxh on 2021/10/23.
//

#ifndef SAMPLEENCLAVE_UTIL_H
#define SAMPLEENCLAVE_UTIL_H

#include <string>
#include <vector>
using namespace std;

string Enc(string key, string meg);
string Dec(string key, string meg) ;

//随机加密
string RndPt(const string &pt);
//按照空格分割
vector<string> splitBy(string str,char x) ;


#endif //SAMPLEENCLAVE_UTIL_H
