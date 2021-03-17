/*
 Copyright 2017 Intel Corporation

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

#include "poet_enclave_t.h"

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <float.h>

#include <algorithm>
#include <map>
#include <vector>
#include <iterator>
#include <cctype>

#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include <sgx_tkey_exchange.h>
#include <sgx_utils.h> // sgx_get_key, sgx_create_report
#include <sgx_key.h>

#include "parson.h"

#include "poet.h"
#include "error.h"
#include "zero.h"
#include "hex_string.h"
#include "public_key_util.h"

#include "utils_enclave.h"
#include "auto_handle_sgx.h"

namespace sp = sawtooth::poet;

typedef struct {
    sgx_ec256_private_t privateKey;
    sgx_ec256_public_t publicKey;
    bool initialized;
} PoetSignUpData;

/* WaitCertificate */
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
    WaitCertificate waitCert;
} WaitCertificateData;

PoetSignUpData gPoetSignupData;

WaitCertificateData gWaitCertData;

//POET duration length in bytes
static const size_t DURATION_LENGTH_BYTES = 32;

#if defined(SGX_SIMULATOR)
    static const bool IS_SGX_SIMULATOR = true;
#else
    static const bool IS_SGX_SIMULATOR = false;
#endif

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
/*
ECDSA public key generated. Note the 8 magic bytes are removed and
x and y component are changed to little endian . The public key is hard coded in the enclave
*/
//  DRD generated public key
static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0xC0, 0x8C, 0x9F, 0x45, 0x59, 0x1A, 0x9F, 0xAE, 0xC5, 0x1F, 0xBC, 0x3E, 0xFB, 0x4F, 0x67, 0xB1,
        0x93, 0x61, 0x45, 0x9E, 0x30, 0x27, 0x10, 0xC4, 0x92, 0x0F, 0xBB, 0xB2, 0x69, 0xB0, 0x16, 0x39
    },
    {
        0x5D, 0x98, 0x6B, 0x24, 0x2B, 0x52, 0x46, 0x72, 0x2A, 0x35, 0xCA, 0xE0, 0xA9, 0x1A, 0x6A, 0xDC,
        0xB8, 0xEB, 0x32, 0xC8, 0x1C, 0x2B, 0x5A, 0xF1, 0x23, 0x1F, 0x6C, 0x6E, 0x30, 0x00, 0x96, 0x4F
    }
};


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XX Declaration of static helper functions                         XX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

static void printf(
    const char* fmt,
    ...
    );

static void Log(
    int         level,
    const char* fmt,
    ...);

static void CreateSignupReportData(
    const char*                 pOriginatorPublicKeyHash,
    const sgx_ec256_public_t*   pPoetPublicKey,
    sgx_report_data_t*          pReportData
    );

static void clearWaitCertificate(WaitCertificate *waitCert);

static void serializeWaitCert(
    WaitCertificate waitCert,
    char* outSerializedWaitCertificate,
    size_t inSerializedWaitCertificateLength
    );

static uint64_t getBlockNumFromSerWaitCert(
    const char* pSerializedWaitCert
    );

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XX External interface                                             XX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
/*
This ecall is a wrapper of sgx_ra_init to create the trusted
KE exchange key context needed for the remote attestation
SIGMA API's. Input pointers aren't checked since the trusted stubs
copy them into EPC memory.

@param p_context Pointer to the location where the returned key
    context is to be copied.
@return Any error returned during the initialization process.
*/
poet_err_t ecall_Initialize(sgx_ra_context_t *p_context)
{
    poet_err_t result = POET_SUCCESS;

    try {
        /* sgx initialization function where the ECDSA generated
        public key is passed as one of the parameters
        returns the context to the application
        */
        sgx_status_t ret = sgx_ra_init(&g_sp_pub_key, false, p_context);
        sp::ThrowSgxError(ret, "Failed to initialize Remote Attestation.");

        gPoetSignupData.initialized = false;
    } catch (sp::PoetError& e) {
        Log(
            POET_LOG_ERROR,
            "Error in poet enclave(ecall_Initialize): %04X -- %s",
            e.error_code(),
            e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    } catch (...) {
        Log(POET_LOG_ERROR, "Unknown error in poet enclave(ecall_Initialize)");
        result = POET_ERR_UNKNOWN;
    }

    return result;
} // ecall_Initialize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
poet_err_t ecall_CreateErsatzEnclaveReport(
    sgx_target_info_t* targetInfo,
    sgx_report_t* outReport
    )
{
    poet_err_t result = POET_SUCCESS;

    try {
        sp::ThrowIfNull(targetInfo, "targetInfo is not valid");
        sp::ThrowIfNull(outReport, "outReport is not valid");

        Zero(outReport, sizeof(*outReport));

        // Create a relatively useless enclave report.  Well....the report
        // itself is not useful for anything except that it can be used to
        // create SGX quotes, which contain potentially useful information
        // (like the enclave basename, mr_enclave, etc.).
        sp::ThrowSgxError(
            sgx_create_report(targetInfo, nullptr, outReport),
            "Failed to create report.");
    } catch (sp::PoetError& e) {
        Log(
            POET_LOG_ERROR,
            "Error in poet enclave(ecall_CreateErsatzEnclaveReport): %04X "
            "-- %s",
            e.error_code(),
            e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    } catch (...) {
        Log(
            POET_LOG_ERROR,
            "Unknown error in poet enclave(ecall_CreateErsatzEnclaveReport)");
        result = POET_ERR_UNKNOWN;
    }

    return result;
} // ecall_CreateErsatzEnclaveReport


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
poet_err_t ecall_CreateSignupData(
    const sgx_target_info_t* inTargetInfo,
    const char* inOriginatorPublicKeyHash,
    sgx_ec256_public_t* outPoetPublicKey,
    sgx_report_t* outEnclaveReport
    )
{
    poet_err_t result = POET_SUCCESS;

    try {
        sp::ThrowIfNull(inTargetInfo, "Target info pointer is NULL");
        sp::ThrowIfNull(
            inOriginatorPublicKeyHash,
            "Originator public key hash pointer is NULL");
        sp::ThrowIfNull(outPoetPublicKey, "PoET public key pointer is NULL");
        sp::ThrowIfNull(outEnclaveReport, "SGX report pointer is NULL");

        // First we need to generate a PoET public/private key pair.  The ECC
        // state handle cleans itself up automatically.
        Intel::SgxEcc256StateHandle eccStateHandle;

        sgx_status_t ret = sgx_ecc256_open_context(&eccStateHandle);
        sp::ThrowSgxError(ret, "Failed to create ECC256 context");

        ret = sgx_ecc256_create_key_pair(
                &gPoetSignupData.privateKey,
                &gPoetSignupData.publicKey,
                eccStateHandle);
        sp::ThrowSgxError(
            ret,
            "Failed to create PoET public/private key pair");

        // Create the report data we want embedded in the enclave report.
        sgx_report_data_t reportData = { 0 };
        CreateSignupReportData(
            inOriginatorPublicKeyHash,
            &gPoetSignupData.publicKey,
            &reportData);

        ret = sgx_create_report(inTargetInfo, &reportData, outEnclaveReport);
        sp::ThrowSgxError(ret, "Failed to create enclave report");

        gPoetSignupData.initialized = true;

        // Give the caller a copy of the PoET public key
        memcpy(
            outPoetPublicKey,
            &gPoetSignupData.publicKey,
            sizeof(*outPoetPublicKey));
    } catch (sp::PoetError& e) {
        Log(
            POET_LOG_ERROR,
            "Error in poet enclave(ecall_CreateSignupData): %04X -- %s",
            e.error_code(),
            e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    } catch (...) {
        Log(
            POET_LOG_ERROR,
            "Unknown error in poet enclave(ecall_CreateSignupData)");
        result = POET_ERR_UNKNOWN;
    }

    return result;
} // ecall_CreateSignupData


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
poet_err_t ecall_VerifySignupInfo(
    const sgx_target_info_t* inTargetInfo,
    const char* inOriginatorPublicKeyHash,
    const sgx_ec256_public_t* inPoetPublicKey,
    sgx_report_t* outEnclaveReport
    )
{
    poet_err_t result = POET_SUCCESS;

    try {
        sp::ThrowIfNull(
            inTargetInfo,
            "Target info pointer is NULL");
        sp::ThrowIfNull(
            inOriginatorPublicKeyHash,
            "Originator public key hash pointer is NULL");
        sp::ThrowIfNull(
            inPoetPublicKey,
            "PoET public key pointer is NULL");
        sp::ThrowIfNull(
            outEnclaveReport,
            "Enclave report pointer is NULL");

        // Create the report data we think should be given the OPK hash and the
        // PPK.
        sgx_report_data_t expectedReportData = { 0 };
        CreateSignupReportData(
            inOriginatorPublicKeyHash,
            inPoetPublicKey,
            &expectedReportData);

        // Create the enclave report for the caller.
        sgx_status_t ret =
            sgx_create_report(
                inTargetInfo,
                &expectedReportData,
                outEnclaveReport);
        sp::ThrowSgxError(ret, "Failed to create enclave report");
    } catch (sp::PoetError& e) {
        Log(
            POET_LOG_ERROR,
            "Error in poet enclave(ecall_VerifySignupInfo): %04X -- %s",
            e.error_code(),
            e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    } catch (...) {
        Log(
            POET_LOG_ERROR,
            "Unknown error in poet enclave(ecall_VerifySignupInfo)");
        result = POET_ERR_UNKNOWN;
    }

    return result;
} // ecall_VerifySignupInfo

poet_err_t ecall_InitializeWaitCertificate(
    const char* inPreviousWaitCertificate,
    size_t inPreviousWaitCertificateLen,
    const char* inValidatorId,
    size_t inValidatorIdLen,
    uint8_t* outDuration,
    size_t inDurationLenBytes
    )
{
    poet_err_t result = POET_SUCCESS;
    try{
        sp::ThrowIfNull(
            inPreviousWaitCertificate,
            "Previous wait certificate is NULL. It can be empty but not NULL");

        sp::ThrowIfNull(
            inValidatorId,
            "Validator ID is NULL");

        sp::ThrowIfNull(
            outDuration,
            "outDuration is NULL");

        sp::ThrowIf<sp::ValueError>(!gPoetSignupData.initialized,
            "PPK not created. Cannot initialize wait certificate");

        // POET engine needs 8 bytes(64 bit) duration to derive wait time.
        // In Wait certificate we store 32 bytes (256 bit) duration
        sp::ThrowIf<sp::ValueError>(
            (inDurationLenBytes != DURATION_LENGTH_BYTES/4),
            "Expected 8 bytes duration (truncated) ");

        // Create random duration
        uint8_t duration[DURATION_LENGTH_BYTES];
        sgx_status_t ret = sgx_read_rand(duration, DURATION_LENGTH_BYTES);
        sp::ThrowSgxError(ret,
            "Failed to generate duration for wait certificate");

        uint64_t prevBlockNum = 0;

        // If previous wait certificate is null or length is 0 is zero its genesis block
        if ( (inPreviousWaitCertificateLen == 0)
            || (inPreviousWaitCertificate == nullptr) ) {
            prevBlockNum = 0;
        } else {
            const size_t prevWaitCertLen = strnlen(inPreviousWaitCertificate,
                                            inPreviousWaitCertificateLen + 1);

            sp::ThrowIf<sp::ValueError>((prevWaitCertLen == 0),
                    "Wait certificate length cannot be zero for non-genenis block");

            if (prevWaitCertLen != inPreviousWaitCertificateLen) {
                sp::ThrowIf<sp::ValueError>(true,
                    "Wait certificate length mismatch");
            }
            prevBlockNum
                = getBlockNumFromSerWaitCert(inPreviousWaitCertificate);
        }

        //clear wait certificate before initializing wait certificate
        clearWaitCertificate(&gWaitCertData.waitCert);

        gWaitCertData.waitCert.block_num = prevBlockNum + 1;
        gWaitCertData.waitCert.validator_id = inValidatorId;

        // Truncate duration to 8 bytes
        // POET engine needs 8 bytes(64 bit) duration to derive wait time
        for(size_t i = 0; i < DURATION_LENGTH_BYTES/4; i++) {
            outDuration[i] = duration[i];
        }

        // Reverse duration array to make in big endian before
        // converting to Hex string
        for(size_t i = 0; i < DURATION_LENGTH_BYTES/2; i++){
            uint8_t temp = duration[i];
            duration[i] = duration[(DURATION_LENGTH_BYTES - 1) - i];
            duration[(DURATION_LENGTH_BYTES - 1) - i] = temp;
        }

        gWaitCertData.waitCert.duration.clear();
        gWaitCertData.waitCert.duration= sp::BinaryToHexString(duration,
                                                    DURATION_LENGTH_BYTES);
        // Wait certificate is initialized
        gWaitCertData.initialized = true;
    } catch (sp::PoetError& e) {
            Log(POET_LOG_ERROR,
                "Error in poet enclave(ecall_InitializeWaitCertificate):"
                " %04X -- %s",
                e.error_code(),
                e.what());
            ocall_SetErrorMessage(e.what());
            result = e.error_code();
    } catch (...) {
            Log(POET_LOG_ERROR,
            "Unknown error in poet enclave(ecall_InitializeWaitCertificate)");
            result = POET_ERR_UNKNOWN;
    }
    return result;
} // ecall_InitializeWaitCertificate

poet_err_t ecall_FinalizeWaitCertificate(
    const char* inPreviousWaitCertificate,
    size_t inPreviousWaitCertificateLen,
    const char* inPrevBlockId,
    size_t inPrevBlockIdLen,
    const char* inPrevWaitCertificateSig,
    size_t inPrevWaitCertificateSigLen,
    const char* inBlockSummary,
    size_t inBlockSummaryLen,
    uint64_t inWaitTime,
    char* outSerializedWaitCertificate,
    size_t inSerializedWaitCertificateLen,
    sgx_ec256_signature_t* outWaitCertificateSignature)
{
    poet_err_t result = POET_SUCCESS;

    try{
        sp::ThrowIfNull(
            inPreviousWaitCertificate,
            "Previous wait certificate is NULL");

        sp::ThrowIfNull(
            inPrevBlockId,
            "Previous BlockId is NULL");
        sp::ThrowIf<sp::ValueError>(!inPrevBlockIdLen,
                   "Previous BlockId length must be non-zero");

        sp::ThrowIfNull(
            inPrevWaitCertificateSig,
            "Previous WaitCertificate Signature is NULL");

        sp::ThrowIfNull(
            inBlockSummary,
            "Block Summary is NULL");

        sp::ThrowIf<sp::ValueError>(!inBlockSummaryLen,
                   "Block summary length must be non-zero");

        sp::ThrowIfNull(outSerializedWaitCertificate,
                   "Output parameter OutSerializedWaitCertificate is NULL");

        sp::ThrowIfNull(
            outWaitCertificateSignature,
            "output parameter outWaitCertificateSignature is NULL");

        sp::ThrowIf<sp::ValueError>(!gPoetSignupData.initialized, 
                    "PPK not created. Cannot finalize wait certificate");

        sp::ThrowIf<sp::ValueError>(!gWaitCertData.initialized,
                    "Wait certificate not initialized."
                    "Cannot finalize wait certificate");

        size_t prevBlockNum = 0;
        size_t currBlockNum = 0;

        // If previous wait certificate is null or length is 0 then its genesis block
        if((inPreviousWaitCertificateLen == 0)
            || (inPreviousWaitCertificate == nullptr)) {
             prevBlockNum = 0;
        }
        else {
                const size_t prevWaitCertLen = strnlen(inPreviousWaitCertificate,
                                            inPreviousWaitCertificateLen + 1);

                sp::ThrowIf<sp::ValueError>(
                        (prevWaitCertLen == 0),
                        "Wait certificate length cannot be zero for non-genenis block");

                if (prevWaitCertLen != inPreviousWaitCertificateLen) {
                    sp::ThrowIf<sp::ValueError>(true,
                            "Wait certificate length mismatch");
                }
                prevBlockNum =
                    getBlockNumFromSerWaitCert(inPreviousWaitCertificate);
        }

        currBlockNum = prevBlockNum + 1;

        // TODO: Need to maintain a map of block_num as key and
        // waitCertificate as value
        // Allow waitcerificate for same block number if previous block id
        // is different. This is to handle fork resolution for same block number
        // with different previous block id
         if(currBlockNum != gWaitCertData.waitCert.block_num) {
            sp::ThrowIf<sp::ValueError>(true,
                "Block number in wait certificate does not match");
        }

        gWaitCertData.waitCert.previous_block_id = (char *)inPrevBlockId;
        gWaitCertData.waitCert.prev_wait_cert_sig = (char *)inPrevWaitCertificateSig;
        gWaitCertData.waitCert.block_summary = (char *)inBlockSummary;
        gWaitCertData.waitCert.wait_time = inWaitTime;

        // Serialize wait certificate
        serializeWaitCert(gWaitCertData.waitCert,
                            outSerializedWaitCertificate, 
                            inSerializedWaitCertificateLen);

        Intel::SgxEcc256StateHandle eccStateHandle;

        sgx_status_t ret = sgx_ecc256_open_context(&eccStateHandle);
        sp::ThrowSgxError(ret, "Failed to create ECC256 context");

        // Sign serialized wait certificate
        ret =   sgx_ecdsa_sign(
                reinterpret_cast<const uint8_t *>(outSerializedWaitCertificate),
                static_cast<int32_t>(strnlen(outSerializedWaitCertificate,
                                                inSerializedWaitCertificateLen)),
                const_cast<sgx_ec256_private_t *>(&gPoetSignupData.privateKey),
                outWaitCertificateSignature,
                eccStateHandle);

        sp::ThrowSgxError(ret, "Failed to sign wait certificate");

        //Clear wait cerificate since it's contents is serialized and consumed
        clearWaitCertificate(&gWaitCertData.waitCert);
        gWaitCertData.initialized = false;

    } catch (sp::PoetError& e) {
        Log(POET_LOG_ERROR,
            "Error in poet enclave(ecall_FinalizeWaitCertificate):"
            " %04X -- %s",
            e.error_code(),
            e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    } catch (...) {
        Log(POET_LOG_ERROR,
            "Unknown error in poet enclave(ecall_FinalizeWaitCertificate)");
        result = POET_ERR_UNKNOWN;
    }
    return result;
} // ecall_FinalizeWaitCertificate

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
poet_err_t ecall_VerifyWaitCertificate(
    const char* inSerializedWaitCertificate,
    const sgx_ec256_signature_t* inWaitCertificateSignature,
    const sgx_ec256_public_t* inPoetPublicKey
    )
{
    poet_err_t result = POET_SUCCESS;

    try {
        sp::ThrowIfNull(
            inSerializedWaitCertificate,
            "Serialized certificate pointer is NULL");
        sp::ThrowIfNull(
            inWaitCertificateSignature,
            "Certificate signature pointer is NULL");
        sp::ThrowIfNull(inPoetPublicKey, "PoET public key pointer is NULL");

        // Verify the signature of the serialized wait certificate. The handle
        // will close automatically for us.
        Intel::SgxEcc256StateHandle eccStateHandle;

        sgx_status_t ret = sgx_ecc256_open_context(&eccStateHandle);
        sp::ThrowSgxError(ret, "Failed to create ECC256 context");

        uint8_t signatureCheckResult;
        ret =
            sgx_ecdsa_verify(
                reinterpret_cast<const uint8_t *>(inSerializedWaitCertificate),
                static_cast<uint32_t>(strlen(inSerializedWaitCertificate)),
                inPoetPublicKey,
                const_cast<sgx_ec256_signature_t *>(inWaitCertificateSignature),
                &signatureCheckResult,
                eccStateHandle);
        sp::ThrowSgxError(ret, "Failed to verify wait certificate signature");
        sp::ThrowIf<sp::ValueError>(
            SGX_EC_VALID != signatureCheckResult,
            "Wait certificate signature is invalid");
    } catch (sp::PoetError& e) {
        Log(
            POET_LOG_ERROR,
            "Error in poet enclave(ecall_VerifyWaitCertificate): %04X -- %s",
            e.error_code(),
            e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    } catch (...) {
        Log(
            POET_LOG_ERROR,
            "Unknown error in poet enclave(ecall_VerifyWaitCertificate)");
        result = POET_ERR_UNKNOWN;
    }

    return result;
} // ecall_VerifyWaitCertificate


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XX Internal helper functions                                      XX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void printf(
    const char* fmt,
    ...
    )
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_Print(buf);
} // printf

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void Log(
    int         level,
    const char* fmt,
    ...
    )
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_Log(level, buf);
} // Log

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void CreateSignupReportData(
    const char*                 pOriginatorPublicKeyHash,
    const sgx_ec256_public_t*   pPoetPublicKey,
    sgx_report_data_t*          pReportData
    )
{
    // We will put the following in the report data SHA256(OPK_HASH|PPK).

    // WARNING - WARNING - WARNING - WARNING - WARNING - WARNING - WARNING
    //
    // If anything in this code changes the way in which the actual enclave
    // report data is represented, the corresponding code that verifies
    // the report data has to be change accordingly.
    //
    // WARNING - WARNING - WARNING - WARNING - WARNING - WARNING - WARNING

    // Canonicalize the originator public key hash string to ensure a consistent
    // format.  For capricious reasons, use upper case for hex letters.
    std::string hashString;
    std::transform(
        pOriginatorPublicKeyHash,
        pOriginatorPublicKeyHash + strlen(pOriginatorPublicKeyHash),
        std::back_inserter(hashString),
        [](char c) {
            return std::toupper(c);
        });

    // Encode the public key and make it uppercase to canonicalize it and
    // append it to the hash string.
    std::string hexString(sp::EncodePublicKey(pPoetPublicKey));
    std::transform(
        hexString.begin(),
        hexString.end(),
        std::back_inserter(hashString),
        [](char c) {
            return std::toupper(c);
        });

    // Now we put the SHA256 hash into the report data for the
    // report we will request.
    //
    // NOTE - we are putting the hash directly into the report
    // data structure because it is (64 bytes) larger than the SHA256
    // hash (32 bytes) but we zero it out first to ensure that it is
    // padded with known data.
    Zero(pReportData, sizeof(*pReportData));
    sgx_status_t ret =
        sgx_sha256_msg(
            reinterpret_cast<const uint8_t *>(hashString.c_str()),
            static_cast<uint32_t>(hashString.size()),
            reinterpret_cast<sgx_sha256_hash_t *>(pReportData));
    sp::ThrowSgxError(ret, "Failed to retrieve SHA256 hash of report data");
} // CreateSignupReportData


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void clearWaitCertificate(WaitCertificate *waitCert) {

    waitCert->block_num = 0;
    waitCert->previous_block_id.clear();
    waitCert->validator_id.clear();
    waitCert->block_summary.clear();
    waitCert->duration.clear();
    waitCert->wait_time = 0;
} // clearWaitCertificate

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void serializeWaitCert(WaitCertificate waitCert,
                       char* outSerializedWaitCertificate,
                       size_t inSerializedWaitCertificateLength
                      ) {
    // Serialize the wait certificate to a JSON string
    JsonValue waitCertValue(json_value_init_object());
    sp::ThrowIf<sp::RuntimeError>(
        !waitCertValue.value,
        "WaitCertification serialization failed on creation of JSON "
        "object.");

    JSON_Object* waitCertObject = json_value_get_object(waitCertValue);
    sp::ThrowIfNull(
        waitCertObject,
        "WaitCertification serialization failed on retrieval of JSON "
        "object.");

    JSON_Status jret = json_object_dotset_number(
                        waitCertObject,
                        "block_number",
                        waitCert.block_num);
    sp::ThrowIf<sp::RuntimeError>(
        jret != JSONSuccess,
        "WaitCertificate serialization failed on block_number.");

    jret = json_object_dotset_string(
                waitCertObject,
                "duration_id",
                waitCert.duration.c_str());
    sp::ThrowIf<sp::RuntimeError>(
        jret != JSONSuccess,
        "WaitCertificate serialization failed on duration_id.");

    jret = json_object_dotset_string(
                waitCertObject,
                "prev_wait_cert_sig",
                waitCert.prev_wait_cert_sig.c_str());
    sp::ThrowIf<sp::RuntimeError>(
        jret != JSONSuccess,
        "WaitCertificate serialization failed on prev_wait_cert_sig.");

    jret = json_object_dotset_string(
                waitCertObject,
                "prev_block_id",
                waitCert.previous_block_id.c_str());
    sp::ThrowIf<sp::RuntimeError>(
        jret != JSONSuccess,
        "WaitCertificate serialization failed on prev_block_id.");

    jret = json_object_dotset_string(
                waitCertObject,
                "block_summary",
                waitCert.block_summary.c_str());
    sp::ThrowIf<sp::RuntimeError>(
        jret != JSONSuccess,
        "WaitCertificate serialization failed on block_summary.");

    jret = json_object_dotset_string(
                waitCertObject,
                "validator_id",
                waitCert.validator_id.c_str());
    sp::ThrowIf<sp::RuntimeError>(
        jret != JSONSuccess,
        "WaitCertificate serialization failed on validator_id.");

    jret = json_object_dotset_number(
                        waitCertObject,
                        "wait_time",
                        waitCert.wait_time);
    sp::ThrowIf<sp::RuntimeError>(
        jret != JSONSuccess,
        "WaitCertificate serialization failed on wait_time.");

    size_t serializedSize = json_serialization_size(waitCertValue);
    sp::ThrowIf<sp::ValueError>(
        inSerializedWaitCertificateLength < serializedSize,
        "WaitCertificate buffer (outSerializedWaitCertificate) is too "
        "small");

    jret = json_serialize_to_buffer(
                waitCertValue,
                outSerializedWaitCertificate,
                inSerializedWaitCertificateLength);
    sp::ThrowIf<sp::RuntimeError>(
        jret != JSONSuccess,
        "WaitCertificate serialization failed.");

} // serializeWaitCert

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
uint64_t getBlockNumFromSerWaitCert(const char* pSerializedWaitCert) {
    uint64_t blockNum;

    JsonValue parsed(json_parse_string(pSerializedWaitCert));
    sp::ThrowIf<sp::ValueError>(
        !parsed.value,
        "Failed to parse Wait Certificate");

    JSON_Object* pObject = json_value_get_object(parsed);

    blockNum = json_object_dotget_number(pObject, "block_number");

    return blockNum;
} // getBlockNumFromSerWaitCert
