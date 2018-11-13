/*
 Copyright 2018 Intel Corporation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
------------------------------------------------------------------------------
*/

#define DURATION_LENGTH_BYTES 32

typedef struct {
    sgx_ec256_private_t privateKey;
    sgx_ec256_public_t publicKey;
    bool initialized;
} PoetSignUpData;

/* Holder for binary representation of WaitCertificate */
typedef struct
{
    std::string duration;
    std::string prev_wait_cert_sig;
    std::string previous_block_id;
    std::string block_summary;
    uint64_t block_num;
    std::string validator_id;
    uint64_t wait_time;
} WaitCertificate;

typedef struct {
    bool initialized;
    uint64_t block_num; 
    WaitCertificate waitCert;
} WaitCertificateData;

