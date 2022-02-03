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
#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/time.h>
#include "oneitem.h"
#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif
/*#define ENCLAVE_FILENAME "/home/lvsiyi/experiments/sqludf/SampleEnclave/libenclave.signed.so"
#define SECOND_TO_MRCROSECOND (1000000)*/

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "/usr/lib/enclave.signed.so"

extern sgx_enclave_id_t eid;    /* global enclave id */

#if defined(__cplusplus)
extern "C" {
#endif
    //void ret_error_support(sgx_status_t ret);
    size_t get_file_size(const char *filename);
    bool read_file_to_buf(char *filename, uint8_t *buf, size_t bsize);
    bool write_buf_to_file(char *filename, const uint8_t *buf, size_t bsize, long offset);
    bool write_buf();
    bool seal_and_save_data(char *encrypt_data, char *filename);
    bool getKey(sgx_enclave_id_t eid);
    bool getStat(sgx_enclave_id_t eid);
    bool getDel(sgx_enclave_id_t eid);
    bool sealState(sgx_enclave_id_t eid);
    bool read_unseal_insert(char *keyfilename, char *statefilename, char *keyword, int keysize, int id, char *BlockInd, int lengthInd, char *BlockW, int lengthW);
    sgx_status_t initialize_enclave(void);
    bool parse_BlockInd(char *BlockInd, char *labelInd, char *labelwStar);
    bool parse_BlockW(char *BlockW, char *labelw, char *res);
    bool parse_BlockDel(char *BlockDel, char *labeldel, char *labelwdel);
    bool initKey();
    bool insertone();
    bool deleteidx(int ind);

    


#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
