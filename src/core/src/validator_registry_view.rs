/*
 * Copyright 2018 Intel Corporation
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

use crypto::sha2::Sha512;
use crypto::digest::Digest;
use validator_registry_tp::validator_registry_validator_info::ValidatorRegistryValidatorInfo;
use service::Poet2Service;
use std::error;
use std::fmt;
use sawtooth_sdk::consensus::engine::BlockId;
use validator_registry_validator_info;
use validator_registry_signup_info::*;

#[derive(Debug, Clone)]
pub struct VRVStateError;

impl fmt::Display for VRVStateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid state found")
    }
}

impl error::Error for VRVStateError {
    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

fn _vr_namespace_prefix() -> String {
        let mut sha = Sha512::new();
        sha.input_str("validator_registry");
        sha.result_str()[..6].to_string()
}

fn _to_address(addressable_key: &String) -> String {
    let mut sha = Sha512::new();
    sha.input_str(addressable_key);
    _vr_namespace_prefix() + &sha.result_str()[..64].to_string()
}

fn _as_validatorInfo(validatorInfoStr: String) -> ValidatorRegistryValidatorInfo {
    let validator_info : ValidatorRegistryValidatorInfo = serde_json::from_str(&validatorInfoStr).unwrap();
    return validator_info;
}

pub fn get_validator_info_for_validator_id(
    validator_id: &String,
    block_id: &BlockId,
    service: &mut Poet2Service)
    -> Result<validator_registry_validator_info::ValidatorRegistryValidatorInfo, VRVStateError> {

    let validator_id_addr = _to_address(validator_id);
    let state_data = service.get_state(block_id.clone(), &validator_id_addr)
                            .expect("Failed to get state for validator id key");
    if let Some(raw_value) = state_data.get(&validator_id_addr) {
        let parsed: Result<String, _> = String::from_utf8(raw_value.to_vec());
        if let Ok(parsed_value) = parsed {
            return Ok(_as_validatorInfo(parsed_value));
       }
   }

    Err(VRVStateError)
}

pub fn get_poet_pubkey_for_validator_id(
    validator_id: &String,
    block_id: &BlockId,
    service: &mut Poet2Service)
    -> Result<String, VRVStateError> {

    let validator_info = get_validator_info_for_validator_id(&validator_id, &block_id.clone(), service);

    if validator_info.is_ok() {
       let validator_info_parsed = validator_info.unwrap();
       return Ok(validator_info_parsed.signup_info.poet_public_key);
    }

    Err(VRVStateError)
}

