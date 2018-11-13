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

#include <stdio.h>
#include "common.h"
#include "poet_enclave.h"
#include "poet.h"
#include "error.h"
#include <iostream>
#include <vector>

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool _is_sgx_simulator()
{
    return 0 != Poet_IsSgxSimulator();
} // _is_sgx_simulator

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Poet::Poet(
    const std::string& enclaveModulePath,
    const std::string& spid
    )
{
    poet_err_t ret = POET_SUCCESS;
    try {
        MyLog(POET_LOG_INFO, "Initializing SGX Poet enclave\n");
        
        ret = Poet_Initialize(
            enclaveModulePath.c_str(),
            spid.c_str(),
            MyLog
            );          
        ThrowPoetError(ret);

        StringBuffer mrEnclaveBuffer(Poet_GetEnclaveMeasurementSize());
        StringBuffer basenameBuffer(Poet_GetEnclaveBasenameSize());

        ThrowPoetError(
            Poet_GetEnclaveCharacteristics(
                mrEnclaveBuffer.data(),
                mrEnclaveBuffer.length,
                basenameBuffer.data(),
                basenameBuffer.length));

        this->mr_enclave = mrEnclaveBuffer.str();
        this->basename = basenameBuffer.str();
    } catch(...) {
        MyLog(POET_LOG_INFO, "Enclave initialization failed\n");
        ret = POET_ERR_UNKNOWN;
        ThrowPoetError(ret);
    }
}// Poet::Poet

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Poet::~Poet()
{
    try {
        Poet_Terminate();
        TerminateInternal();
    } catch (...) {
    }
} // Poet::~Poet

Poet* Poet::getInstance(
    const std::string& enclaveModulePath,
    const std::string& spid)
{
    if(!Poet::instance){
        Poet::instance = new Poet(enclaveModulePath, spid);
    }
    return Poet::instance;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::string Poet::get_epid_group()
{
    StringBuffer epidGroupBuffer(Poet_GetEpidGroupSize());
    poet_err_t ret = POET_SUCCESS;

    try {
        ThrowPoetError(
        Poet_GetEpidGroup(
            epidGroupBuffer.data(),
            epidGroupBuffer.length));
    } catch(...) {
        MyLog(POET_LOG_INFO, "Exception in get EPID group\n");
        ret = POET_ERR_UNKNOWN;
        ThrowPoetError(ret);
    }

    return std::string(epidGroupBuffer.str());  
} // Poet::get_epid_group

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void Poet::set_signature_revocation_list(
    const std::string& signature_revocation_list
    )
{
    poet_err_t ret = POET_SUCCESS;
    try {
        ThrowPoetError(
            Poet_SetSignatureRevocationList(signature_revocation_list.c_str()));
    } catch(...) {
        MyLog(POET_LOG_INFO, "Exception in set signature revocation list\n");
        ret = POET_ERR_UNKNOWN;
        ThrowPoetError(ret);
    }
} // Poet::set_signature_revocation_lists

