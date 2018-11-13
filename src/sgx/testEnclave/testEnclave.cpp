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

#include <iostream>
#include <sstream>
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include "sgx_error.h"
#include "../libpoet_shared/poet_defs.h"

#include "poet_enclave_u.h"

#include "testEnclave.h"
#include "zero.h"
#include "public_key_util.h"
#include "signature_util.h"
#include "utils.h"
#include "hex_string.h"

namespace sp = sawtooth::poet;

sgx_enclave_id_t gEnclaveId;

// This macro calculates the length of the actual data portion of the
// base 64 encoding of a buffer with x bytes PLUS the additional byte
// needed for the string terminator.
#define BASE64_SIZE(x) (static_cast<size_t>(((((x) - 1) / 3) * 4 + 4) + 1))


int main(int argc, char **argv) {

    loadEnclave();

    sgx_ra_context_t raContext;
    poet_err_t poetError = POET_SUCCESS;
    test_ecall_Initialize(gEnclaveId,&raContext,&poetError);

    sgx_target_info_t targetInfo = { 0 };
    sgx_epid_group_id_t gid = { 0 };
    sgx_status_t ret = sgx_init_quote(&targetInfo, &gid);

    sgx_report_t enclaveReport = { 0 };
    test_ecall_CreateErsatzEnclaveReport(gEnclaveId, &poetError,
	                                     &targetInfo, &enclaveReport);


    memset(&targetInfo,0,sizeof(targetInfo));
    memset(&gid,0,sizeof(gid));
    ret = sgx_init_quote(&targetInfo, &gid);

    memset(&enclaveReport,0,sizeof(enclaveReport));
    std::string opk_hash = "ABCD";
    sgx_ec256_public_t outPoetPublicKey;

    test_ecall_CreateSignupData(gEnclaveId,
                                &poetError,
                                &targetInfo,
                                opk_hash.c_str(),
                                &outPoetPublicKey,
                                &enclaveReport
                                );

    test_ecall_VerifySignupInfo(gEnclaveId,
                                &poetError,
                                &targetInfo,
                                opk_hash.c_str(),
                                &outPoetPublicKey,
                                &enclaveReport
                                );
   

    std::string inPreviousWaitCertificate = "";
    std::string inValidatorId = "1234";
    std::string inPrevWaitCertificateSig = "";
    sgx_ec256_signature_t prevWaitCertSign;
    uint8_t duration[8];

    if (inPrevWaitCertificateSig.length() > 0) {
        sp::Poet_DecodeSignature(&prevWaitCertSign, inPrevWaitCertificateSig.c_str());
    } 

    test_ecall_InitializeWaitCertificate(gEnclaveId,
                                         &poetError,
                                         inPreviousWaitCertificate.c_str(),
                                         inPreviousWaitCertificate.length(),
                                         inValidatorId.c_str(),
                                         inValidatorId.length(),
                                         &prevWaitCertSign,
                                         &outPoetPublicKey,
                                         duration,
                                         sizeof(duration)
                                         );

    std::string inPrevBlockId = "abc";
    std::string inBlockSummary = "test";
    std::string inPreviousWaitCertificateSig = "";
    uint64_t inWaitTime = 10;
    
    StringBuffer outSerializedWaitCert(Poet_GetWaitCertificateSize());
    StringBuffer outSerializedWaitCertSign(Poet_GetSignatureSize());
    sgx_ec256_signature_t outWaitCertificateSignature;

    test_ecall_FinalizeWaitCertificate(gEnclaveId,
                                      &poetError,
                                      inPreviousWaitCertificate.c_str(),
                                      inPreviousWaitCertificate.length(),
                                      inPrevBlockId.c_str(), 
                                      inPrevBlockId.length(),
                                      inPreviousWaitCertificateSig.c_str(), 
                                      inPreviousWaitCertificateSig.length(),
                                      inBlockSummary.c_str(), 
                                      inBlockSummary.length(),
                                      inWaitTime,
                                      outSerializedWaitCert.data(), 
                                      outSerializedWaitCert.length,
                                      &outWaitCertificateSignature);

    // Encode the certificate signature returned
    sp::Poet_EncodeSignature(outSerializedWaitCertSign.data(),
                             outSerializedWaitCertSign.length,
                             &outWaitCertificateSignature);

    const char *inSerializedWaitCertificate = outSerializedWaitCert.data();
    sgx_ec256_signature_t *inWaitCertificateSignature = &outWaitCertificateSignature;
    sgx_ec256_public_t *inPoetPublicKey = &outPoetPublicKey;   
    test_ecall_VerifyWaitCertificateSignature(gEnclaveId,
                                               &poetError,
                                               inSerializedWaitCertificate,
                                               inWaitCertificateSignature,
                                               inPoetPublicKey);


    return 0;
}

void test_ecall_Initialize(sgx_enclave_id_t enclaveId,
	                	      sgx_ra_context_t *raContextPtr, 
	 					              poet_err_t *poetErrorPtr) {

	sgx_status_t ret =  ecall_Initialize(
                                enclaveId,
                                poetErrorPtr,
                                raContextPtr);

	if(ret != SGX_SUCCESS) {
		printf("Error: ecall_Initialize\n");
	} else {
		printf("Success: ecall_Initialize\n");
	}

}

void test_ecall_CreateErsatzEnclaveReport(sgx_enclave_id_t enclaveId,
                            			  poet_err_t *poetErrorPtr,
                            			  sgx_target_info_t *targetInfoPtr,
                            			  sgx_report_t *enclaveReportPtr) {

	sgx_status_t ret =  ecall_CreateErsatzEnclaveReport(
                                enclaveId,
                                poetErrorPtr,
                                targetInfoPtr,
                                enclaveReportPtr);

	if(ret != SGX_SUCCESS) {
		printf("Error: ecall_CreateErsatzEnclaveReport\n");
	} else {
		printf("Success: ecall_CreateErsatzEnclaveReport\n");
	}

}

void test_ecall_CreateSignupData(sgx_enclave_id_t enclaveId,
                                 poet_err_t *poetErrorPtr,
                                 const sgx_target_info_t* inTargetInfo,
                                 const char* inOriginatorPublicKeyHash,
                                 sgx_ec256_public_t* outPoetPublicKey,
                                 sgx_report_t* outEnclaveReport) {
    
    sgx_status_t ret = ecall_CreateSignupData(
                                 enclaveId,
                                 poetErrorPtr,
                                 inTargetInfo,
                                 inOriginatorPublicKeyHash,
                                 outPoetPublicKey,
                                 outEnclaveReport);

    if(ret != SGX_SUCCESS) {
        printf("Error: test_ecall_CreateSignupData\n");
    } else {
        printf("Success: test_ecall_CreateSignupData\n");
    }

}

void test_ecall_InitializeWaitCertificate(sgx_enclave_id_t enclaveId,
                                          poet_err_t *poetErrorPtr,
                                          const char* inPreviousWaitCertificate, 
                                          size_t inPreviousWaitCertificateLen, 
                                          const char* inValidatorId, 
                                          size_t inValidatorIdLen,
                                          const sgx_ec256_signature_t* inPreviousWaitCertificateSig,
                                          const sgx_ec256_public_t* inPoetPublicKey,
                                          uint8_t* outDuration,
                                          size_t inDurationLenBytes) {


    sgx_status_t ret = ecall_InitializeWaitCertificate(
                                enclaveId,
                                poetErrorPtr,
                                inPreviousWaitCertificate,
                                inPreviousWaitCertificateLen,
                                inValidatorId, 
                                inValidatorIdLen,
                                inPreviousWaitCertificateSig,
                                inPoetPublicKey,
                                outDuration,
                                inDurationLenBytes);

    if(ret != SGX_SUCCESS) {
        printf("Error: test_ecall_InitializeWaitCertificate\n");
    } else {
        printf("Success: test_ecall_InitializeWaitCertificate\n");
    }

}
                                     

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
                                          sgx_ec256_signature_t* outWaitCertificateSignature) {


    sgx_status_t ret = ecall_FinalizeWaitCertificate(enclaveId,
                                                    poetErrorPtr,
                                                    inPreviousWaitCertificate,
                                                    inPreviousWaitCertificateLen,
                                                    inPrevBlockId, 
                                                    inPrevBlockIdLen,
                                                    inPreviousWaitCertificateSig, 
                                                    inPreviousWaitCertificateSigLen,
                                                    inBlockSummary, 
                                                    inBlockSummaryLen,
                                                    inWaitTime,
                                                    outSerializedWaitCertificate, 
                                                    outSerializedWaitCertificateLen,
                                                    outWaitCertificateSignature);


    if(ret != SGX_SUCCESS) {
        printf("Error: test_ecall_FinalizeWaitCertificate\n");
    } else {
        printf("Success: test_ecall_FinalizeWaitCertificate\n");
    }

}

void test_ecall_VerifyWaitCertificateSignature(sgx_enclave_id_t enclaveId,
                                               poet_err_t *poetErrorPtr,
                                               const char* inSerializedWaitCertificate,
                                               const sgx_ec256_signature_t* inWaitCertificateSignature,
                                               const sgx_ec256_public_t* inPoetPublicKey) {

    sgx_status_t ret = ecall_VerifyWaitCertificateSignature(enclaveId,
                                                     poetErrorPtr,
                                                     inSerializedWaitCertificate,
                                                     inWaitCertificateSignature,
                                                     inPoetPublicKey);

    if(ret != SGX_SUCCESS) {
        printf("Error: test_ecall_VerifyWaitCertificateSignature\n");
    } else {
        printf("Success: test_ecall_VerifyWaitCertificateSignature\n");
    }

}

void test_ecall_VerifySignupInfo(sgx_enclave_id_t enclaveId,
                                 poet_err_t *poetErrorPtr,
                                 const sgx_target_info_t* inTargetInfo,
                                 const char* inOriginatorPublicKeyHash,
                                 const sgx_ec256_public_t* inPoetPublicKey,
                                 sgx_report_t* outEnclaveReport) {

    sgx_status_t ret = ecall_VerifySignupInfo(enclaveId,
                                                     poetErrorPtr,
                                                     inTargetInfo,
                                                     inOriginatorPublicKeyHash,
                                                     inPoetPublicKey,
                                                     outEnclaveReport);

    if(ret != SGX_SUCCESS) {
        printf("Error: test_ecall_VerifySignupInfo\n");
    } else {
        printf("Success: test_ecall_VerifySignupInfo\n");
    }

}

void loadEnclave() {

    std::string enclaveFilePath = "libpoet_enclave.signed.so";
    sgx_launch_token_t token = { 0 };
    int flags = SGX_DEBUG_FLAG;

    sgx_status_t ret = SGX_SUCCESS;
    int updated = 0;

    ret = sgx_create_enclave(enclaveFilePath.c_str(),
                             flags,
                             &token,
                             &updated,
                             &gEnclaveId,
                             NULL);

    if(ret != SGX_SUCCESS) {
        printf("Error: loadEnclave\n");
    } else {
        printf("Success: loadEnclave\n");
    }
}

extern "C" {

    void ocall_Print(
        const char *str
        )
    {
       std::cout << str;
    } 

    void ocall_Log(
        int level,
        const char *str
        )
    {
       std::cout << "Log: " << str;
    } 

    void ocall_SetErrorMessage(
        const char* message
        )
    {
        std::cout << "Error: " << message;
    }

} // extern "C"


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
size_t Poet_GetWaitCertificateSize()
{
    return 2*1024; // Empirically these are big enough
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
size_t Poet_GetSignatureSize()
{
    // We encode the components of the signature separately to avoid
    // potential for struct alignment issues
    return
        BASE64_SIZE(
            sizeof(static_cast<sgx_ec256_signature_t *>(nullptr)->x) +
            sizeof(static_cast<sgx_ec256_signature_t *>(nullptr)->y));
}