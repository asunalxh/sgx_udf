#pragma once
#include "AES.h"

#include <stdio.h>
#include <stdlib.h>
#include <mysql.h>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>

using namespace std;

class dblp {
public:
    int id;
    string journal = "";
public:
    dblp(){
    };
    ~dblp(){
    }
};

class sdblp {
public:
    int sid;
    string sjournal = "";
public:
    sdblp(){
    };
    ~sdblp(){
    }
};

class enc_dblp {
public:
    int id;
    string enc_journal = "";
public:
    enc_dblp(){
    };
    ~enc_dblp(){
    }
};

string parseInd(int ind);
bool GetValue(dblp *item, int ind);
bool deletebyInd(char *tabname, int ind);
int insertValue(enc_dblp eitem);
string EncryptionAES(const string& strSrc);
string DecryptionAES(const string& strSrc);
string RndPt(const string& pt);
