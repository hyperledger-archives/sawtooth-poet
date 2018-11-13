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

#pragma once 
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "sgx_urts.h"
#include "sgx_key_exchange.h"

#include "poet.h"

namespace sawtooth {
    namespace poet {

        class Enclave {
        public:
            typedef std::vector<uint8_t> buffer_t;

            Enclave();
            virtual ~Enclave();

            void Load(
                const std::string& inEnclaveFilePath
                );
            void Unload();

            size_t GetQuoteSize() const
            {
                return this->quoteSize;
            } // GetQuoteSize

            void GetEpidGroup(
                sgx_epid_group_id_t outEpidGroup
                );
            void GetEnclaveCharacteristics(
                sgx_measurement_t* outEnclaveMeasurement,
                sgx_basename_t* outEnclaveBasename
                );
            void SetSpid(
                const std::string& inSpid
                );
            void SetDataDirectory(
                const std::string& inDataDirectory
                )
            {
                dataDirectory = inDataDirectory;
            } // SetDataDirectory

            void SetSignatureRevocationList(
                const std::string& inSignatureRevocationList
                );

            void CreateSignupData(
                const std::string& inOriginatorPublicKeyHash,
                sgx_ec256_public_t* outPoetPublicKey,
                buffer_t& outEnclaveQuote
                );
            
            void VerifySignupInfo(
                const std::string& inOriginatorPublicKeyHash,
                const sgx_ec256_public_t* inPoetPublicKey,
                const sgx_quote_t* inEnclaveQuote,
                size_t inEnclaveQuoteSize
                );
            
            void Enclave_InitializeWaitCertificate(
                const char* inPreviousWaitCertificate,
                size_t inPreviousWaitCertificateLen, 
                const char* inValidatorId,
                size_t inValidatorIdLen,
                const sgx_ec256_signature_t* inPreviousWaitCertificateSig,
                const sgx_ec256_public_t* inPoetPublicKey,
                uint8_t* duration,
                size_t inDurationLen
                );
            void Enclave_FinalizeWaitCertificate(
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
                size_t outSerializedWaitCertificateLen, 
                sgx_ec256_signature_t* outWaitCertificateSignature
                );

            void VerifyWaitCertificate(
                const std::string& inSerializedWaitCertificate,
                const sgx_ec256_signature_t* inWaitCertificateSignature,
                const sgx_ec256_public_t* inPoetPublicKey
                );

        private:
            void ThrowPoetError(
                poet_err_t err
                );
            void LoadEnclave();
            sgx_status_t CallSgx(
                std::function<sgx_status_t (void)> sgxCall, 
                int retries = 5, 
                int retryDelayMs = 100
                );

            static void QuerySgxStatus();
        private:
            std::string enclaveFilePath;
            sgx_enclave_id_t enclaveId;
            sgx_ra_context_t raContext;

            size_t quoteSize;

            std::string signatureRevocationList;
            sgx_spid_t spid;
            std::string dataDirectory;
        }; // class Enclave

    } // namespace poet
} // namespace sawtooth
