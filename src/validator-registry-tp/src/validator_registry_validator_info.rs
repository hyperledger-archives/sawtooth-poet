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

use validator_registry_signup_info::ValidatorRegistrySignupInfo;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ValidatorRegistryValidatorInfo {
    // The human readable name of the endpoint
    pub name : String,

    // The validator's public key(as in txn hdr
    pub id : String,

    pub signup_info : ValidatorRegistrySignupInfo,

    // The header sign for a ValidatorRegistryPayload txn
    pub txn_id : String
}

impl Default for ValidatorRegistryValidatorInfo {
    fn default() -> ValidatorRegistryValidatorInfo {
        ValidatorRegistryValidatorInfo {
            name : String::new(),
            id : String::new(),
            signup_info : ValidatorRegistrySignupInfo::default(),
            txn_id : String::new(),
        }
    }
}
