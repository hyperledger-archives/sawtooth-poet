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

#include <json-c/json.h>

#include "poet_enclave.h"
#include "common.h"
#include "poet.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
WaitCertificate::WaitCertificate(
    const std::string& serializedCertificate,
    const std::string& signature
    ) :
    serialized(serializedCertificate),
    signature(signature)
{
    PyLog(POET_LOG_INFO, "Create SGX Wait Certificate");
    this->deserialize(this->serialized);
} // WaitCertificate::WaitCertificate

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
WaitCertificate::WaitCertificate(
    const std::string& prevWaitCertificate,
    const std::string& prevBlockId,
    const std::string& prevWaitCertificateSig,
    const std::string& blockSummary,
    uint64_t waitTime
    )
{
    StringBuffer serializedBuffer(Poet_GetWaitCertificateSize());
    StringBuffer signatureBuffer(Poet_GetSignatureSize());

    poet_err_t ret =
        Poet_FinalizeWaitCertificate(
            prevWaitCertificate.c_str(),
            prevWaitCertificate.length(),
            prevBlockId.c_str(),
            prevBlockId.length(),
            prevWaitCertificateSig.c_str(),
            prevWaitCertificateSig.length(),
            blockSummary.c_str(),
            blockSummary.length(),
            waitTime,
            serializedBuffer.data(),
            serializedBuffer.length,
            signatureBuffer.data(),
            signatureBuffer.length
        );
    ThrowPoetError(ret);

    this->serialized = serializedBuffer.str();
    this->signature = signatureBuffer.str();
    this->deserialize(this->serialized);
} // WaitCertificate::WaitCertificate

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool WaitCertificate::_InitializeWaitCertificate(
    const std::string& prevWaitCertificate,
    const std::string& validatorId,
    uint8_t *duration,
    size_t durationLen
    )
{
     poet_err_t ret =
        Poet_InitializeWaitCertificate(
            prevWaitCertificate.c_str(),
            prevWaitCertificate.length(),
            validatorId.c_str(),
            validatorId.length(),
            duration,
            durationLen
            );
    ThrowPoetError(ret);

    return (ret == POET_SUCCESS);
} // WaitCertificate::_InitializeWaitCertificate

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
WaitCertificate* WaitCertificate::_FinalizeWaitCertificate(
    const std::string& prevWaitCertificate,
    const std::string& prevBlockId,
    const std::string& prevWaitCertificateSig,
    const std::string& blockSummary,
    uint64_t waitTime
    )
{
    return new WaitCertificate(prevWaitCertificate, prevBlockId,
            prevWaitCertificateSig, blockSummary, waitTime);
} // WaitCertificate::_FinalizeWaitCertificate

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool initialize_wait_certificate(
    const std::string& prevWaitCertificate,
    const std::string& validatorId,
    const std::string& prevWaitCertificateSig,
    const std::string& poetPubKey,
    uint8_t *duration,
    size_t durationLen
    )
{
    return WaitCertificate::_InitializeWaitCertificate(prevWaitCertificate,
            validatorId, duration, durationLen);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
WaitCertificate* finalize_wait_certificate(
    const std::string& prevWaitCertificate,
    const std::string& prevBlockId,
    const std::string& prevWaitCertificateSig,
    const std::string& blockSummary,
    uint64_t waitTime
    )
{
    return WaitCertificate::_FinalizeWaitCertificate(prevWaitCertificate,
            prevBlockId, prevWaitCertificateSig, blockSummary, waitTime);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void _destroy_wait_certificate(WaitCertificate *waitCert)
{
    if(waitCert != nullptr) {
        delete waitCert;
    }
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
WaitCertificate* WaitCertificate::_WaitCertificateFromSerialized(
    const std::string& serializedCertificate,
    const std::string& signature
    )
{
    return new WaitCertificate(serializedCertificate, signature);
} // WaitCertificate::_WaitCertificateFromSerialized

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::string WaitCertificate::identifier() const
{
    if (this->signature.empty()) {
        return NULL_IDENTIFIER;
    }

    return CreateIdentifier(this->signature);
} // WaitCertificate::identifier

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::string WaitCertificate::serialize() const
{
    return this->serialized;
} // WaitCertificate::serialize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void WaitCertificate::deserialize(
    const std::string&  serializedCertificate
    )
{
    json_object* jsonObject
        = json_tokener_parse(serializedCertificate.c_str());
    if (!jsonObject) {
        throw ValueError("Failed to parse serialized wait certificate");
    }

    json_object* jsonValue = NULL;

    // Use alphabetical order for the keys
    if (json_object_object_get_ex(jsonObject, "block_number", &jsonValue)) {
        this->block_num = json_object_get_int64(jsonValue);
    } else {
        throw
            ValueError(
                "Failed to extract BlockNumber from serialized wait "
                "certificate");
    }

    if (json_object_object_get_ex(jsonObject, "block_summary", &jsonValue)) {
        this->block_summary = json_object_get_string(jsonValue);
    } else {
        throw
            ValueError(
                "Failed to extract BlockSummary from serialized wait "
                "certificate");
    }

    if (json_object_object_get_ex(jsonObject, "duration_id", &jsonValue)) {
        this->duration = json_object_get_string(jsonValue);
    } else {
        throw
            ValueError(
                "Failed to extract Duration from serialized wait "
                "certificate");
    }

    if (json_object_object_get_ex(jsonObject, "prev_block_id", &jsonValue)) {
        this->previous_block_id = json_object_get_string(jsonValue);
    } else {
        throw
            ValueError(
                "Failed to extract PreviousBlockId from serialized wait "
                "certificate");
    }

    if (json_object_object_get_ex(jsonObject, "prev_wait_cert_sig", &jsonValue)) {
        this->prev_wait_cert_sig = json_object_get_string(jsonValue);
    } else {
        throw
            ValueError(
                "Failed to extract PrevWaitCertSig from serialized wait "
                "certificate");
    }

    if (json_object_object_get_ex(jsonObject, "validator_id", &jsonValue)) {
        this->validator_id = json_object_get_string(jsonValue);
    } else {
        throw
            ValueError(
                "Failed to extract ValidatorId from serialized wait "
                "certificate");
    }

    if (json_object_object_get_ex(jsonObject, "wait_time", &jsonValue)) {
        this->wait_time = json_object_get_int64(jsonValue);
    } else {
        throw
            ValueError(
                "Failed to extract WaitTime from serialized wait "
                "certificate");
    }
} // WaitCertificate::deserialize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
WaitCertificate* deserialize_wait_certificate(
    const std::string& serialized_certificate,
    const std::string& signature
    )
{
    return
        WaitCertificate::_WaitCertificateFromSerialized(
            serialized_certificate,
            signature);
} // deserialize_wait_certificate

bool _verify_wait_certificate(
    const std::string& serializedWaitCertificate,
    const std::string& waitCertificateSignature,
    const std::string& poetPublicKey
    )
{
    PyLog(POET_LOG_INFO, "Verify SGX Wait Certificate");

    poet_err_t ret =
        Poet_VerifyWaitCertificate(
            serializedWaitCertificate.c_str(),
            waitCertificateSignature.c_str(),
            poetPublicKey.c_str() );
    ThrowPoetError(ret);

    if(ret == POET_SUCCESS) return true;
    return false;
}