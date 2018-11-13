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

#include "poet_enclave.h"
#include "common.h"
#include "poet.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
_SignupData::_SignupData(
    const std::string& originatorPublicKeyHash
    )
{
    // Create some buffers for receiving the output parameters
    std::vector<char> poetPublicKey(Poet_GetPublicKeySize());
    std::vector<char> enclaveQuote(Poet_GetEnclaveQuoteSize());
    
    // Create the signup data
    poet_err_t result = 
        Poet_CreateSignupData(
            originatorPublicKeyHash.c_str(),
            &poetPublicKey[0],
            poetPublicKey.size(),
            &enclaveQuote[0],
            enclaveQuote.size());
    ThrowPoetError(result);
    
    // Save the output parameters in our properties
    this->poet_public_key = std::string(&poetPublicKey[0]);
    this->enclave_quote = std::string(&enclaveQuote[0]);
} // _SignupData::_SignupData
    
_SignupData* _SignupData::CreateSignupData(
    const std::string& originatorPublicKeyHash
    )
{
    return new _SignupData(originatorPublicKeyHash);
} // _SignupData::CreateSignupData


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
_SignupData* _create_signup_data(
    const std::string& originator_public_key_hash
    )
{
    return
        _SignupData::CreateSignupData(originator_public_key_hash);
} // _create_signup_data

void _destroy_signup_data(_SignupData* signup_data) 
{
    if(signup_data != NULL) {

        delete signup_data;
    }
}
