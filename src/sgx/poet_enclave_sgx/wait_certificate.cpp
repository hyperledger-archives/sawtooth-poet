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

#include <json-c/json.h>

#include "poet_enclave.h"
#include "common.h"
#include "poet.h"
#include <iostream>

WaitCertificate::WaitCertificate() {}

WaitCertificate* WaitCertificate::_WaitCertificateFromSerialized(
    const std::string& serializedCertificate,
    const std::string& signature
    )
{

    WaitCertificate *waitcert = new WaitCertificate();
    waitcert->serialized = serializedCertificate;
    waitcert->signature = signature;

    waitcert->deserialize(waitcert->serialized);

    return waitcert;
} // WaitCertificate::_WaitCertificateFromSerialized

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
    //PyLog(POET_LOG_INFO, "Verify SGX Wait Certificate");

    poet_err_t ret =
        Poet_VerifyWaitCertificate(
            serializedWaitCertificate.c_str(),
            waitCertificateSignature.c_str(),
            poetPublicKey.c_str() );
    ThrowPoetError(ret);

    if(ret == POET_SUCCESS) return true;
    return false;
}

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

    this->serialized = std::string(serializedBuffer.data());
    this->signature = std::string(signatureBuffer.data());
    this->deserialize(this->serialized);
} // WaitCertificate::WaitCertificate


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
poet_err_t WaitCertificate::_InitializeWaitCertificate(
    const std::string& prevWaitCertificate,
    const std::string& validatorId,
    const std::string& prevWaitCertificateSig,
    const std::string& poetPubKey,
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
            prevWaitCertificateSig.c_str(),
            prevWaitCertificateSig.length(),
            poetPubKey.c_str(),
            poetPubKey.length(),
            duration,
            durationLen
            );
        
    ThrowPoetError(ret);
    
} // WaitCertificate::_InitializeWaitCertificate

WaitCertificate* WaitCertificate::_FinalizeWaitCertificate(
    const std::string& prevWaitCertificate,
    const std::string& prevBlockId,
    const std::string& prevWaitCertificateSig,
    const std::string& blockSummary,
    uint64_t waitTime
    )
{ 
    return new WaitCertificate(prevWaitCertificate, prevBlockId, prevWaitCertificateSig, blockSummary, waitTime);
} // WaitCertificate::_FinalizeWaitCertificate


poet_err_t initialize_wait_certificate(
    const std::string& prevWaitCertificate,
    const std::string& validatorId,
    const std::string& prevWaitCertificateSig,
    const std::string& poetPubKey,
    uint8_t *duration,
    size_t durationLen
    )
{ 
    return WaitCertificate::_InitializeWaitCertificate(prevWaitCertificate, validatorId,
                                    prevWaitCertificateSig, poetPubKey, duration, durationLen);
}

WaitCertificate* finalize_wait_certificate(
    const std::string& prevWaitCertificate,
    const std::string& prevBlockId,
    const std::string& prevWaitCertificateSig,
    const std::string& blockSummary,
    uint64_t waitTime
    )
{
    return WaitCertificate::_FinalizeWaitCertificate(prevWaitCertificate, prevBlockId, prevWaitCertificateSig, blockSummary, waitTime);
}

void _destroy_wait_certificate(WaitCertificate *waitCert)
{
    if(waitCert != NULL) {
        delete waitCert;
    }
}

std::string WaitCertificate::serialize() const
{
    return this->serialized;
} // WaitCertificate::serialize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void WaitCertificate::deserialize(
    const std::string&  serializedCertificate
    )
{
    json_object* jsonObject = json_tokener_parse(serializedCertificate.c_str());
    if (!jsonObject) {
        throw ValueError("Failed to parse serialized wait certificate");
    }

    json_object* jsonValue = NULL;
    // Use alphabetical order for the keys
    if (json_object_object_get_ex(jsonObject, "block_summary", &jsonValue)) {
        
        this->block_summary = json_object_get_string(jsonValue);
         
    } else {
        throw
            ValueError(
                "Failed to extract BlockHash from serialized wait certificate");
    }
    if (json_object_object_get_ex(jsonObject, "block_number", &jsonValue)) {  
        this->block_num = json_object_get_int(jsonValue);     
    } else {
        throw
            ValueError(
                "Failed to extract BlockHash from serialized wait certificate");
    }

    if (json_object_object_get_ex(jsonObject, "duration_id", &jsonValue)) {
        this->duration = json_object_get_string(jsonValue);
    } else {
        throw
            ValueError(
                "Failed to extract Duration from serialized wait "
                "certificate");
    }

    if (json_object_object_get_ex(jsonObject, "prev_wait_cert_sig", &jsonValue)) {
        this->prev_wait_cert_sig = json_object_get_string(jsonValue);
    } else {
        throw
            ValueError(
                "Failed to extract PoetBlockId from serialized wait "
                "certificate");
    }

    if (json_object_object_get_ex(jsonObject, "prev_block_id", &jsonValue)) {
        this->previous_block_id = json_object_get_string(jsonValue);
    } else {
        throw
            ValueError(
                "Failed to extract PreviousCertID from serialized wait "
                "certificate");
    }

    if (json_object_object_get_ex(jsonObject, "validator_id", &jsonValue)) {
        this->validator_id = json_object_get_string(jsonValue);
    } else {
        throw
            ValueError(
                "Failed to extract ValidatorAddress from serialized wait "
                "certificate");
    }
} // WaitCertificate::deserialize

std::string WaitCertificate::identifier() const
{
    if (this->signature.empty()) {
        return NULL_IDENTIFIER;
    }
    return CreateIdentifier(this->signature);
} // WaitCertificate::identifier
