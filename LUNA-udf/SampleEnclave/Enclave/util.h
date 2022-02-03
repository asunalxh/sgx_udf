#pragma once
#include "AES.h"
//#include "Base64.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

using namespace std;



string EncryptionAES(const char* g_key, const char* g_iv, const string& strSrc);
string DecryptionAES(const char* g_key, const char* g_iv, const string& strSrc);
