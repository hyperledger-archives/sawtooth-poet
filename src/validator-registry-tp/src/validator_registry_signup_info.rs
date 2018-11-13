/*
 * Copyright 2018 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -----------------------------------------------------------------------------
 */

use serde_json;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Default)]
pub struct SignupInfoProofData {
    pub verification_report : String,
    pub signature : String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct ValidatorRegistrySignupInfo {
    // Encoded public key corresponding to private key used by PoET to sign
    // wait certificates
    pub poet_public_key : String,

    // Information that can be used internally to verify the validity of
    // the signup information stored as an opaque buffer
    pub proof_data : String,

    // A string corresponding to the anti-Sybil ID for the enclave that
    // generated the signup information
    pub anti_sybil_id : String,

    // The nonce associated with the signup info.  Note that this must match
    // the nonce provided when the signup info was created.
    pub nonce : String,
}

impl Default for ValidatorRegistrySignupInfo {
    fn default() -> ValidatorRegistrySignupInfo {
        ValidatorRegistrySignupInfo {
            poet_public_key : String::new(),
            proof_data : String::new(),
            anti_sybil_id : String::new(),
            nonce : String::new(),
        }
    }
}

