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

#include "poet.h"
#include "log.h"
#include "utils.h"
#include "hex_string.h"
#include "enclave.h"
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string.h>
#include <iterator>
#include <algorithm>
#include "sgx_ukey_exchange.h" /*To call untrusted key exchange library i.e., sgx_ra_get_msg1() and sgx_ra_proc_msg2() */

#include "error.h"

#include "zero.h"
#include "public_key_util.h"
#include "signature_util.h"

#define CERTIFICATE_ID_LENGTH 16
#define MAX_ADDRESS_LENGTH 66
#define MIN_ADDRESS_LENGTH 26

namespace sp = sawtooth::poet;

// This macro calculates the length of the actual data portion of the
// base 64 encoding of a buffer with x bytes PLUS the additional byte
// needed for the string terminator.
#define BASE64_SIZE(x) (static_cast<size_t>(((((x) - 1) / 3) * 4 + 4) + 1))

sp::Enclave g_Enclave;
static bool g_IsInitialized = false;
static std::string g_LastError;

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XX Declaration of static helper functions                         XX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

static void Poet_SetLastError(
    const char* msg
    );


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XX External interface                                             XX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
int Poet_IsSgxSimulator()
{
#if defined(SGX_SIMULATOR)
    return 1;
#else // defined(SGX_SIMULATOR)
    return 0;
#endif // defined(SGX_SIMULATOR)
} // Poet_IsSgxSimulator

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
poet_err_t Poet_GetLastErrorMessage(
    char* outMessage,
    size_t inMessageLength
    )
{
    poet_err_t ret = POET_SUCCESS;
    if (outMessage) {
        strncpy_s(
            outMessage,
            inMessageLength,
            g_LastError.c_str(),
            g_LastError.length());
    }

    return ret;
} // Poet_GetLastErrorMessage

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
poet_err_t Poet_Initialize(
    const char* inPathToEnclave,
    const char* inSpid,
    poet_log_t logFunction
    )
{
    poet_err_t ret = POET_SUCCESS;

    try {
        if (!g_IsInitialized)
        {
            sp::ThrowIfNull(inPathToEnclave, "Enclave path string is NULL");
            sp::ThrowIfNull(inSpid, "SPID buffer is NULL");           
            sp::SetLogFunction(logFunction);
            g_Enclave.SetSpid(inSpid);
            g_Enclave.Load(inPathToEnclave);
            g_IsInitialized = true;
        }
    } catch (sp::PoetError& e) {
        Poet_SetLastError(e.what());
        ret = e.error_code();
    } catch(std::exception& e) {
        Poet_SetLastError(e.what());
        ret = POET_ERR_UNKNOWN;
    } catch(...) {
        Poet_SetLastError("Unexpected exception");
        ret = POET_ERR_UNKNOWN;
    }

    return ret;
} // Poet_Initialize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
poet_err_t Poet_Terminate()
{
    // Unload the enclave
    poet_err_t ret = POET_SUCCESS;

    try {
        if (g_IsInitialized) {
            g_Enclave.Unload();
            g_IsInitialized = false;
        }
    } catch (sp::PoetError& e) {
        Poet_SetLastError(e.what());
        ret = e.error_code();
    } catch (std::exception& e) {
        Poet_SetLastError(e.what());
        ret = POET_ERR_UNKNOWN;
    } catch (...) {
        Poet_SetLastError("Unexpected exception");
        ret = POET_ERR_UNKNOWN;
    }

    return ret;
} // Poet_Terminate

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
size_t Poet_GetEpidGroupSize()
{
    return HEX_STRING_SIZE(sizeof(sgx_epid_group_id_t));
} // Poet_GetEpidGroupSize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
size_t Poet_GetEnclaveMeasurementSize()
{
    return
        HEX_STRING_SIZE(
            sizeof((static_cast<sgx_measurement_t *>(nullptr))->m));
} // Poet_GetEnclaveMeasurementSize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
size_t Poet_GetEnclaveBasenameSize()
{
    return
        HEX_STRING_SIZE(
            sizeof((static_cast<sgx_quote_t *>(nullptr))->basename));
} // Poet_GetEnclaveBasenameSize

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

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
size_t Poet_GetPublicKeySize()
{
    return sp::EncodedPublicKeySize();
} // Poet_GetPublicKeySize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
size_t Poet_GetEnclaveQuoteSize()
{
    return BASE64_SIZE(g_Enclave.GetQuoteSize());
} // Poet_GetEnclaveQuoteSize


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
poet_err_t Poet_GetEpidGroup(
    char* outEpidGroup,
    size_t inEpidGroupLength
    )
{
     poet_err_t ret = POET_SUCCESS;

     try {
        sp::ThrowIfNull(outEpidGroup, "NULL outEpidGroup");
        sp::ThrowIf<sp::ValueError>(
           inEpidGroupLength < Poet_GetEpidGroupSize(),
           "EPID group buffer is too small");

        // Get the EPID group from the enclave and convert it to big endian
        sgx_epid_group_id_t epidGroup;
        g_Enclave.GetEpidGroup(epidGroup);

        std::reverse(epidGroup, epidGroup + sizeof(epidGroup));

        // Convert the binary data to a hex string and copy it to the caller's
        // buffer
        std::string hexString =
            sp::BinaryToHexString(epidGroup, sizeof(epidGroup));
        strncpy_s(
           outEpidGroup,
           inEpidGroupLength,
           hexString.c_str(),
           hexString.length());
    } catch (sp::PoetError& e) {
        Poet_SetLastError(e.what());
        ret = e.error_code();
    } catch (std::exception& e) {
        Poet_SetLastError(e.what());
        ret = POET_ERR_UNKNOWN;
    } catch (...) {
        Poet_SetLastError("Unexpected exception");
        ret = POET_ERR_UNKNOWN;
    }

    return ret;
} // Poet_GetEpidGroup

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
poet_err_t Poet_GetEnclaveCharacteristics(
    char* outMrEnclave,
    size_t inMrEnclaveLength,
    char* outEnclaveBasename,
    size_t inEnclaveBasenameLength
    )
{
    poet_err_t ret = POET_SUCCESS;

    try {
        sp::ThrowIfNull(outMrEnclave, "NULL outMrEnclave");
        sp::ThrowIf<sp::ValueError>(
           inMrEnclaveLength < Poet_GetEnclaveMeasurementSize(),
           "Enclave measurement buffer is too small");
        sp::ThrowIfNull(outEnclaveBasename, "NULL outEnclaveBasename");
        sp::ThrowIf<sp::ValueError>(
           inEnclaveBasenameLength < Poet_GetEnclaveBasenameSize(),
           "Enclave basename buffer is too small");

        // Get the enclave characteristics and then convert the binary data to
        // hex strings and copy them to the caller's buffers.
        sgx_measurement_t enclaveMeasurement;
        sgx_basename_t enclaveBasename;

        g_Enclave.GetEnclaveCharacteristics(
            &enclaveMeasurement,
            &enclaveBasename);            

        std::string hexString =
            sp::BinaryToHexString(
                enclaveMeasurement.m,
                sizeof(enclaveMeasurement.m));
        strncpy_s(
           outMrEnclave,
           inMrEnclaveLength,
           hexString.c_str(),
           hexString.length());

        hexString =
            sp::BinaryToHexString(
                enclaveBasename.name,
                sizeof(enclaveBasename.name));
        strncpy_s(
           outEnclaveBasename,
           inEnclaveBasenameLength,
           hexString.c_str(),
           hexString.length());
        
    } catch (sp::PoetError& e) {
        Poet_SetLastError(e.what());
        ret = e.error_code();
    } catch (std::exception& e) {
        Poet_SetLastError(e.what());
        ret = POET_ERR_UNKNOWN;
    } catch (...) {
        Poet_SetLastError("Unexpected exception");
        ret = POET_ERR_UNKNOWN;
    }

    return ret;
} // Poet_GetEnclaveCharacteristics

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
poet_err_t Poet_SetSignatureRevocationList(
    const char* inSignatureRevocationList
    )
{
    poet_err_t ret = POET_SUCCESS;

    try {
        sp::ThrowIfNull(
            inSignatureRevocationList,
            "NULL inSignatureRevocationList");

        g_Enclave.SetSignatureRevocationList(inSignatureRevocationList);
    } catch (sp::PoetError& e) {
        Poet_SetLastError(e.what());
        ret = e.error_code();
    } catch (std::exception& e) {
        Poet_SetLastError(e.what());
        ret = POET_ERR_UNKNOWN;
    } catch (...) {
        Poet_SetLastError("Unexpected exception");
        ret = POET_ERR_UNKNOWN;
    }

    return ret;

} // Poet_SetSignatureRevocationList

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
poet_err_t Poet_CreateSignupData(
    const char* inOriginatorPublicKeyHash,
    char* outPoetPublicKey,
    size_t inPoetPublicKeySize,
    char* outEnclaveQuote,
    size_t inEnclaveQuoteSize
    )
{
    poet_err_t result = POET_SUCCESS;

    try {
        // validate params
        sp::ThrowIfNull(inOriginatorPublicKeyHash, "NULL inOriginatorPublicKeyHash");
        sp::ThrowIfNull(outPoetPublicKey, "NULL outPoetPublicKey");
        sp::ThrowIf<sp::ValueError>(
            inPoetPublicKeySize < Poet_GetPublicKeySize(),
            "Public key buffer too small (outPoetPublicKey)");
        sp::ThrowIfNull(outEnclaveQuote, "NULL outEnclaveQuote");
        sp::ThrowIf<sp::ValueError>(
            inEnclaveQuoteSize < Poet_GetEnclaveQuoteSize(),
            "Enclave quote buffer too small (outEnclaveQuote)");

        // Clear out the buffers
        Zero(outPoetPublicKey, inPoetPublicKeySize);
        Zero(outEnclaveQuote, inEnclaveQuoteSize);

        // Have the enclave create the signup data
        sgx_ec256_public_t poetPublicKey = {0};
        sp::Enclave::buffer_t enclaveQuote;

        g_Enclave.CreateSignupData(
            inOriginatorPublicKeyHash,
            &poetPublicKey,
            enclaveQuote);            

        // Encode and copy the data that is to be returned to the caller
        std::string encodedPublicKey(sp::EncodePublicKey(&poetPublicKey));
        strncpy_s(
            outPoetPublicKey,
            inPoetPublicKeySize,
            encodedPublicKey.c_str(),
            encodedPublicKey.length());
        sp::EncodeB64(outEnclaveQuote, inEnclaveQuoteSize, enclaveQuote);
    } catch (sp::PoetError& e) {
        Poet_SetLastError(e.what());
        result = e.error_code();
    } catch (std::exception& e) {
        Poet_SetLastError(e.what());
        result = POET_ERR_UNKNOWN;
    } catch (...) {
        Poet_SetLastError("Unexpected exception");
        result = POET_ERR_UNKNOWN;
    }

    return result;
} // Poet_CreateSignupData


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
poet_err_t Poet_VerifySignupInfo(
    const char* inOriginatorPublicKeyHash,
    const char* inPoetPublicKey,
    const char* inEnclaveQuote
    )
{
    poet_err_t result = POET_SUCCESS;

    try {
        // validate params
        sp::ThrowIfNull(inOriginatorPublicKeyHash, "NULL inOriginatorPublicKeyHash");
        sp::ThrowIfNull(inPoetPublicKey, "NULL inPoetPublicKey");
        sp::ThrowIfNull(inEnclaveQuote, "NULL inEnclaveQuote");

        // Take the encoded public key and decode it
        sgx_ec256_public_t poetPublicKey;
        sp::DecodePublicKey(&poetPublicKey, inPoetPublicKey);

        // Take the encoded enclave quote and turn it into a sgx_quote_t.  We
        // decode into a vector because quote buffers are variable size.
        std::vector<uint8_t> enclaveQuoteBuffer;
        sp::DecodeB64(enclaveQuoteBuffer, inEnclaveQuote);

        // Now let the enclave take over
        g_Enclave.VerifySignupInfo(
            inOriginatorPublicKeyHash,
            &poetPublicKey,
            reinterpret_cast<sgx_quote_t *>(&enclaveQuoteBuffer[0]),
            enclaveQuoteBuffer.size());
    } catch (sp::PoetError& e) {
        Poet_SetLastError(e.what());
        result = e.error_code();
    } catch (std::exception& e) {
        Poet_SetLastError(e.what());
        result = POET_ERR_UNKNOWN;
    } catch (...) {
        Poet_SetLastError("Unexpected exception");
        result = POET_ERR_UNKNOWN;
    }

    return result;
} // Poet_VerifySignupInfo


poet_err_t Poet_InitializeWaitCertificate(
    const char* prevWaitCertificate,
    size_t prevWaitCertificateLen, 
    const char* validatorId,
    size_t validatorIdLen,
    const char* prevWaitCertificateSig,
    size_t prevWaitCertificateSigLen,
    const char* poetPubKey,
    size_t poetPubKeyLen,
    uint8_t *duration,
    size_t durationLen
    )
{
    poet_err_t ret = POET_SUCCESS;
    try {
        // validate params
        sp::ThrowIfNull(prevWaitCertificate, "NULL PreviousWaitCertificate");
        sp::ThrowIfNull(validatorId, "NULL ValidatorId");
        sp::ThrowIfNull(prevWaitCertificateSig, "NULL PrevWaitCertificateSig");
        sp::ThrowIfNull(poetPubKey, "NULL poetPubKey");
                                  
        sgx_ec256_signature_t waitCertificateSignature;
        sgx_ec256_public_t decodedPoetPublicKey;

        // Take the encoded wait certificate signature and PoET public keys and
        // convert them into something that is more convenient to use internally
        if (strnlen(prevWaitCertificateSig, prevWaitCertificateSigLen) > 0) {
            sp::Poet_DecodeSignature(&waitCertificateSignature, prevWaitCertificateSig);
        } 
        
        sp::DecodePublicKey(&decodedPoetPublicKey, poetPubKey);
    
        g_Enclave.Enclave_InitializeWaitCertificate(
            prevWaitCertificate,
            prevWaitCertificateLen,
            validatorId,
            validatorIdLen,
            &waitCertificateSignature,
            &decodedPoetPublicKey,
            duration,
            durationLen);

    } catch (sp::PoetError& e) {
        Poet_SetLastError(e.what());
        ret = e.error_code();
    } catch (std::exception& e) {
        Poet_SetLastError(e.what());
        ret = POET_ERR_UNKNOWN;
    } catch (...) {
        Poet_SetLastError("Unexpected exception");
        ret = POET_ERR_UNKNOWN;
    }

    return ret;
} // Poet_InitialzeWaitCertificate

poet_err_t Poet_FinalizeWaitCertificate(
    const char* prevWaitCertificate,
    size_t prevWaitCertificateLen,
    const char* prevBlockId,
    size_t prevBlockIdLen,
    const char* prevWaitCertificateSig,
    size_t prevWaitCertificateSigLen,
    const char* blockSummary,
    size_t blockSummaryLen,
    uint64_t waitTime,
    char* serializedWaitCertificate,
    size_t serializedWaitCertificateLen,
    char* serializedWaitCertificateSignature,
    size_t serializedWaitCertificateSignatureLen
    )
{
    poet_err_t ret = POET_SUCCESS;
    try {
        // validate params
        sp::ThrowIfNull(prevWaitCertificate, "NULL PrevWaitCertificate");
        sp::ThrowIfNull(prevBlockId, "NULL PoetBlockId");
        sp::ThrowIfNull(prevWaitCertificateSig, "NULL PrevWaitCertificateSignature");
        sp::ThrowIfNull(blockSummary, "NULL BlockSummary");
   
        sgx_ec256_signature_t waitCertificateSignature;

        g_Enclave.Enclave_FinalizeWaitCertificate(
            prevWaitCertificate,
            prevWaitCertificateLen,
            prevBlockId,
            prevBlockIdLen,
            prevWaitCertificateSig,
            prevWaitCertificateSigLen,
            blockSummary,
            blockSummaryLen,
            waitTime,
            serializedWaitCertificate,
            serializedWaitCertificateLen,
            &waitCertificateSignature
            );

        // Encode the certificate signature returned
        sp::Poet_EncodeSignature(
            serializedWaitCertificateSignature,
            serializedWaitCertificateSignatureLen,
            &waitCertificateSignature);
        
    } catch (sp::PoetError& e) {
        Poet_SetLastError(e.what());
        ret = e.error_code();
    } catch (std::exception& e) {
        Poet_SetLastError(e.what());
        ret = POET_ERR_UNKNOWN;
    } catch (...) {
        Poet_SetLastError("Unexpected exception");
        ret = POET_ERR_UNKNOWN;
    }

    return ret;    
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
poet_err_t Poet_VerifyWaitCertificate(
    const char* inSerializedWaitCertificate,
    const char* inWaitCertificateSignature,
    const char* inPoetPublicKey
    )
{
    poet_err_t ret = POET_SUCCESS;

    try {
        // validate params
        sp::ThrowIfNull(
            inSerializedWaitCertificate,
            "NULL inSerializedWaitCertificate");
        sp::ThrowIfNull(
            inWaitCertificateSignature,
            "NULL inWaitCertificateSignature");
        sp::ThrowIfNull(inPoetPublicKey, "NULL inPoetPublicKey");

        sgx_ec256_signature_t waitCertificateSignature;
        sgx_ec256_public_t poetPublicKey;

        // Take the encoded wait certificate signature and PoET public keys and
        // convert them into something that is more convenient to use internally
        sp::Poet_DecodeSignature(
            &waitCertificateSignature,
            inWaitCertificateSignature);
        sp::DecodePublicKey(&poetPublicKey, inPoetPublicKey);

        g_Enclave.VerifyWaitCertificate(
            inSerializedWaitCertificate,
            &waitCertificateSignature,
            &poetPublicKey);
    } catch (sp::PoetError& e) {
        Poet_SetLastError(e.what());
        ret = e.error_code();
    } catch (std::exception& e) {
        Poet_SetLastError(e.what());
        ret = POET_ERR_UNKNOWN;
    } catch (...) {
        Poet_SetLastError("Unexpected exception");
        ret = POET_ERR_UNKNOWN;
    }

    return ret;
} // Poet_VerifyWaitCertificate

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XX Internal helper functions                                      XX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void Poet_SetLastError(
    const char* msg
    )
{
    if (msg) {
        g_LastError = msg;
    }
    else {
        g_LastError = "No error description";
    }
} // Poet_SetLastError
