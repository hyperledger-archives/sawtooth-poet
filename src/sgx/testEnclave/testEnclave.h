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
#include <vector>

// This macro calculates the length of the actual data portion of the
// base 64 encoding of a buffer with x bytes PLUS the additional byte
// needed for the string terminator.
#define BASE64_SIZE(x) (static_cast<size_t>(((((x) - 1) / 3) * 4 + 4) + 1))

size_t Poet_GetWaitCertificateSize();

size_t Poet_GetSignatureSize();

void loadEnclave();

void test_ecall_Initialize(sgx_enclave_id_t enclaveId,
	                	   sgx_ra_context_t *raContextPtr, 
	 					   poet_err_t *poetErrorPtr);

void test_ecall_CreateErsatzEnclaveReport(sgx_enclave_id_t enclaveId,
                            			  poet_err_t *poetErrorPtr,
                            			  sgx_target_info_t *targetInfoPtr,
                            			  sgx_report_t *enclaveReportPtr);


void test_ecall_CreateSignupData(sgx_enclave_id_t enclaveId,
                                 poet_err_t *poetErrorPtr,
                                 const sgx_target_info_t* inTargetInfo,
                                 const char* inOriginatorPublicKeyHash,
                                 sgx_ec256_public_t* outPoetPublicKey,
                                 sgx_report_t* outEnclaveReport);

void test_ecall_VerifySignupInfo(sgx_enclave_id_t enclaveId,
                                 poet_err_t *poetErrorPtr,
                                 const sgx_target_info_t* inTargetInfo,
                                 const char* inOriginatorPublicKeyHash,
                                 const sgx_ec256_public_t* inPoetPublicKey,
                                 sgx_report_t* outEnclaveReport);


void test_ecall_InitializeWaitCertificate(sgx_enclave_id_t enclaveId,
                                          poet_err_t *poetErrorPtr,
                                          const char* inPreviousWaitCertificate, 
                                          size_t inPreviousWaitCertificateLen, 
                                          const char* inValidatorId, 
                                          size_t inValidatorIdLen,
                                          const sgx_ec256_signature_t* inPreviousWaitCertificateSig,
                                          const sgx_ec256_public_t* inPoetPublicKey,
                                          uint8_t* outDuration,
                                          size_t inDurationLenBytes);

void test_ecall_FinalizeWaitCertificate(sgx_enclave_id_t enclaveId,
                                          poet_err_t *poetErrorPtr,
                                          const char* inPreviousWaitCertificate,
                                          size_t inPreviousWaitCertificateLen,
                                          const char* inPrevBlockId, 
                                          size_t inPrevBlockIdLen,
                                          const char* inPreviousWaitCertificateSig, 
                                          size_t inPreviousWaitCertificateSigLen,
                                          const char* inBlockSummary, 
                                          size_t inBlockSummaryLen,
                                          uint64_t inWaitTime,
                                          char* outSerializedWaitCertificate, 
                                          size_t outSerializedWaitCertificateLen,
                                          sgx_ec256_signature_t* outWaitCertificateSignature);

void test_ecall_VerifyWaitCertificateSignature(sgx_enclave_id_t enclaveId,
                                               poet_err_t *poetErrorPtr,
                                               const char* inSerializedWaitCertificate,
                                               const sgx_ec256_signature_t* inWaitCertificateSignature,
                                               const sgx_ec256_public_t* inPoetPublicKey);

class StringBuffer {
public:
    StringBuffer(size_t size) : buffer(size)
    {
        this->length = buffer.size();
    }
    virtual ~StringBuffer() {}

    std::string str()
    {
        return std::string(&this->buffer[0]);
    }

    char* data()
    {
        return &this->buffer[0];
    }

    std::vector<char> buffer;
    size_t length;
}; // class StringBuffer