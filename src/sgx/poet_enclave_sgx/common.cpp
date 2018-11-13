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

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <random>

//#include <Python.h>

#include <crypto++/cryptlib.h>
#include <crypto++/eccrypto.h>
#include <crypto++/asn.h>
#include <crypto++/oids.h>
#include <crypto++/base32.h>
#include <crypto++/integer.h>
#include <crypto++/osrng.h>
#include <crypto++/files.h>
#include <iostream>

#include "poet_enclave.h"
#include "common.h"
#include "c11_support.h"
#include "platform_support.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::string CreateIdentifier(const std::string& signature)
{
    // Compute the digest of the message
    unsigned char digest[CryptoPP::SHA256::DIGESTSIZE];
    CryptoPP::SHA256().CalculateDigest(
        digest,
        (const byte *)signature.data(),
        signature.size()
        );

    CryptoPP::Base32Encoder encoder(NULL, false);
    encoder.Put((byte *)digest, CryptoPP::SHA256::DIGESTSIZE);
    encoder.MessageEnd();

    std::string encoded;
    encoded.resize(encoder.MaxRetrievable());
    encoder.Get((byte *)encoded.data(), encoded.size());

    return encoded.substr(0,16);
} // CreateIdentifier

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ThrowPoetError(
    poet_err_t ret
    )
{
    if (ret != POET_SUCCESS) {
        std::vector<char> value(256);
        Poet_GetLastErrorMessage(&value[0], value.size());
        switch(ret) {
        case POET_SUCCESS:
            return;
        case POET_ERR_UNKNOWN:
            throw UnknownError(std::string(&value[0]));
        case POET_ERR_MEMORY:
            throw  MemoryError(&value[0]);
        case POET_ERR_IO:
            throw  IOError(&value[0]);
        case POET_ERR_RUNTIME:
            throw  RuntimeError(&value[0]);
        case POET_ERR_INDEX:
            throw  IndexError(&value[0]);
        case POET_ERR_DIVIDE_BY_ZERO:
            throw  DivisionByZero(&value[0]);
        case POET_ERR_OVERFLOW:
            throw  OverflowError(&value[0]);
        case POET_ERR_VALUE:
            throw  ValueError(&value[0]);
        case POET_ERR_SYSTEM:
            throw  SystemError(&value[0]);
        case POET_ERR_SYSTEM_BUSY:
            throw  SystemBusyError(&value[0]);
        default:
            throw std::runtime_error(std::string(&value[0]));
        }
    }
} // ThrowPoetError

void MyLog(
     poet_log_level_t logLevel,
     const char* message
     )
{
   printf("%s", message);
}

void MyLogV(
    poet_log_level_t type,
    const char* message,
    ...
    )
{
    const int BUFFER_SIZE = 2048;
    char msg[BUFFER_SIZE] = { '\0' };
    va_list ap;
    va_start(ap, message);
    vsnprintf_s(msg, BUFFER_SIZE, BUFFER_SIZE-1, message, ap);
    va_end(ap);
    MyLog(type, msg);
} // MyLogV


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void InitializePoetEnclaveModule()
{
    // Intentionally left blank
} // InitializePoetEnclaveModule

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void TerminateInternal()
{
    //_SetLogger(NULL);
} // TerminateInternal
