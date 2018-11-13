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
#include <algorithm>
#include <iterator>
#include "utils.h"
#include "signature_util.h"
#include "hex_string.h"

namespace sp = sawtooth::poet;

namespace sawtooth {
    namespace poet {
        
        void Poet_EncodeSignature(
            char* outEncodedSignature,
            size_t inEncodedSignatureLength,
            const sgx_ec256_signature_t* inSignature
            )
        {
            // NOTE - NOTE - NOTE - NOTE - NOTE - NOTE - NOTE - NOTE
            //
            // Before converting the signature to a base 64 string we are going to
            // reverse the signature x and y components as it appears that these large
            // integers seem (I say seem as I don't have access to source code) to be
            // stored in the arrays in little endian.  Therefore, we are going to
            // reverse them so that they are in big endian.
            //
            // NOTE - NOTE - NOTE - NOTE - NOTE - NOTE - NOTE - NOTE

            // We know that the buffer will be no bigger than
            // sizeof(*inSignature) because of potential padding
            std::vector<uint8_t> bigEndianBuffer;
            bigEndianBuffer.reserve(sizeof(*inSignature));

            // Copy the x and y components of the public key into the the buffer,
            // reversing the order of bytes as we do so.
            std::copy(
                std::reverse_iterator<const uint8_t *>(
                    reinterpret_cast<const uint8_t *>(inSignature->x) +
                    sizeof(inSignature->x)),
                std::reverse_iterator<const uint8_t *>(
                    reinterpret_cast<const uint8_t *>(inSignature->x)),
                std::back_inserter(bigEndianBuffer));
            std::copy(
                std::reverse_iterator<const uint8_t *>(
                    reinterpret_cast<const uint8_t *>(inSignature->y) +
                    sizeof(inSignature->y)),
                std::reverse_iterator<const uint8_t *>(
                    reinterpret_cast<const uint8_t *>(inSignature->y)),
                std::back_inserter(bigEndianBuffer));

            // Now convert the signature components to base 64 into the caller's buffer
            sp::EncodeB64(
                outEncodedSignature,
                inEncodedSignatureLength,
                bigEndianBuffer);
        } // Poet_EncodeSignature

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Poet_DecodeSignature(
            sgx_ec256_signature_t *outSignature,
            const char* inEncodedSignature
            )
        {
            // First convert the base 64 string to a buffer of bytes
            std::vector<uint8_t> bigEndianBuffer;
            sp::DecodeB64(bigEndianBuffer, inEncodedSignature);

            // NOTE - NOTE - NOTE - NOTE - NOTE - NOTE - NOTE - NOTE
            //
            // After converting the base 64 string to a signature we are going to
            // reverse the signature x and y components as it appears that these large
            // integers seem (I say seem as I don't have access to source code) to be
            // stored in the arrays in little endian.  Therefore, we are going to
            // reverse them from the big endian format we used when we encoded it.
            //
            // NOTE - NOTE - NOTE - NOTE - NOTE - NOTE - NOTE - NOTE

            // Copy the contents of the buffer into the x and y components of
            // the signature, reversing the order of the bytes as we do so.
            std::copy(
                std::reverse_iterator<uint8_t *>(
                    &bigEndianBuffer[0] + sizeof(outSignature->x)),
                std::reverse_iterator<uint8_t *>(&bigEndianBuffer[0]),
                reinterpret_cast<uint8_t *>(outSignature->x));
            std::copy(
                std::reverse_iterator<uint8_t *>(
                    &bigEndianBuffer[sizeof(outSignature->x)] +
                    sizeof(outSignature->y)),
                std::reverse_iterator<uint8_t *>(
                    &bigEndianBuffer[sizeof(outSignature->x)]),
                reinterpret_cast<uint8_t *>(outSignature->y));
        } // Poet_DecodeSignature

    } // namespace poet
} // namespace sawtooth
