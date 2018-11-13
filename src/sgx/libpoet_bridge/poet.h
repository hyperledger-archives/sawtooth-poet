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

#include "poet_defs.h"
#include <stdlib.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif // _cplusplus


    #define POET_IDENTIFIER_LENGTH 16

    /*
        Tests if libpoet is built against the SGX simulator or the SGX runtime
    */
    int Poet_IsSgxSimulator();

    /*
        Returns the string associated with the last PoET error message.

        outMessage - A pointer to a buffer that, if not NULL, will upon return
            contain the message associated with the error code returned.
        inMessageLength - The size of the buffer pointed to by outMessage.
    */
    poet_err_t Poet_GetLastErrorMessage(
        char* outMessage,
        size_t inMessageLength
        );

    /*
        Start the poet services

        inDataDirectory - A pointer to a string that contains the data
            directory for the validator.
        inPathToEnclave - A pointer to a string that contains the path to the
            enclave DLL.
        inSpid - A pointer to a string that contains the hex encoded SPID.
        logFunction - A pointer to the PoET log function.
    */
    poet_err_t Poet_Initialize(
        const char* inPathToEnclave,
        const char* inSpid,
        poet_log_t logFunction
        );

    /*
        Stop the poet services
    */
    poet_err_t Poet_Terminate();

    /*
        Helper functions to determine buffer sizes for outgoing buffers filled
        in by enclave.
    */
    size_t Poet_GetEpidGroupSize();
    size_t Poet_GetEnclaveMeasurementSize();
    size_t Poet_GetEnclaveBasenameSize();
    size_t Poet_GetWaitCertificateSize();
    size_t Poet_GetSignatureSize();
    size_t Poet_GetPublicKeySize();
    size_t Poet_GetEnclaveQuoteSize();

    /*
        Returns the EPID group as a Hex(base 16) encoded string.

        outEpidGroup - A pointer to a buffer that upon return will contain the
            hex encoded EPID group.
        inEpidGroupLength - The size of the buffer pointed to by outEpidGroup.
            The value to provide for this parameter may be obtained by calling
            Poet_GetEpidGroupSize().
    */
    poet_err_t Poet_GetEpidGroup(
        char* outEpidGroup,
        size_t inEpidGroupLength
        );

    /*
        Returns characteristics about the enclave that can be used later when
        verifying signup information from other validators,

        outMrEnclave - A pointer to a buffer that upon return will contain the
            hex encoded enclave hash (aka, mr_enclave).
        inMrEnclaveLength - The size of the buffer pointed to by outMrEnclave.
            The value to provide for this parameter may be obtained by calling
            Poet_GetEnclaveMeasurementSize().
        outEnclaveBasename - A pointer to a buffer that upon return will contain
            the hex encoded enclave basename.
        inEnclaveBasenameLength - The size of the buffer pointed to by
            outEnclaveBasename.  The value to provide for this parameter may
            be obtained by calling Poet_GetEnclaveBasenameSize().
    */
    poet_err_t Poet_GetEnclaveCharacteristics(
        char* outMrEnclave,
        size_t inMrEnclaveLength,
        char* outEnclaveBasename,
        size_t inEnclaveBasenameLength
        );

    /*
        takes in the results from the IAS server and
        stores the revocation list for future processing

        inSignatureRevocationList - A string containing the signature
            revocation list obtained from IAS.
    */
    poet_err_t Poet_SetSignatureRevocationList(
        const char* inSignatureRevocationList
        );

    /*
        Generate the signup data and a linkable quote that can be used to create the
        IAS attestation verification report (AVR).

        inOriginatorPublicKeyHash - A string representing the SHA256 hash of the
            originator's public key.
        outPoetPublicKey - A pointer to a buffer that upon return will contain
            the hex encoded PoET public key generated.
        inPoetPublicKeySize - The size of the buffer pointed to by
            outPoetPublicKey.  The value to provide for this parameter may be
            obtained by calling Poet_GetPublicKeySize().
        outEnclaveQuote - A pointer to a buffer that upon return will contain
            the base 64 encoded linkable enclave quote.
        inEnclaveQuoteSize - The size of the buffer pointed to by
            outEnclaveQuote.  The value to provide for this parameter may be
            obtained by calling Poet_GetEnclaveQuoteSize().
    */
    poet_err_t Poet_CreateSignupData(
        const char* inOriginatorPublicKeyHash,
        char* outPoetPublicKey,
        size_t inPoetPublicKeySize,
        char* outEnclaveQuote,
        size_t inEnclaveQuoteSize
        );
    
    /*
        Verifies that the signup information provided is valid (as least as far
        as this enclave is concerned).

        inOriginatorPublicKeyHash - A string representing the SHA256 hash of the
            originator's public key.
        inPoetPublicKey - A string representing the hex encoding of the PoET
            public key created for the validator.
        inEnclaveQuote - A string representing the base 64 encoding of the
            enclave quote that the other validator provided to IAS when it
            created its signup information.
    */
    poet_err_t Poet_VerifySignupInfo(
        const char* inOriginatorPublicKeyHash,
        const char* inPoetPublicKey,
        const char* inEnclaveQuote
        );    
    
    /*
        generates duration
        prevWaitCertificate - string representation of serialized previous wait certificate
        validatorId - string representation of validator id
        prevBlockId - string representation of hash of previous block
    */

    poet_err_t Poet_InitializeWaitCertificate(
    	const char* prevWaitCertificate,
    	size_t prevWaitCertificateLen, 
    	const char* validatorId,
    	size_t validatorIdLen,
    	const char* prevWaitCertificateSig,
        size_t prevWaitCertificateSigLen,
        const char* poetPublicKey,
        size_t poetPublicKeyLen,
    	uint8_t *duration,
        size_t durationLen
    	);
    /*
        generates wait certificate
        poetBlockId - string representation of hash of previous block
        blockSummary - string representation of hash of all transactions in a block
    */

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
    	);

    /*
        Verifies that a wait certificate is valid.

        inSerializedWaitCertificate - A string representing a serialized wait
            certificate that was created by a previously-successful call to
            PoET_CreateWaitCertificate().
        inWaitCertificateSignature - A string that contains the base 64 encoded
            ECDSA signature over the serialized wait certificate
            (inSerializedWaitCertificate) using the PoET secret key created when
            the validator created its signup info.  This was returned from a
            successful call to Poet_CreateWaitCertificate().
        inPoetPublicKey - A string representing the encoded PoET public key used
            to verify the wait certificate signature.
    */
    poet_err_t Poet_VerifyWaitCertificate(
        const char* inSerializedWaitCertificate,
        const char* inWaitCertificateSignature,
        const char* inPoetPublicKey
        );

#ifdef __cplusplus
};
#endif // _cplusplus
