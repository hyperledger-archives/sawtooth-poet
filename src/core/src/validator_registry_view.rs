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
use validator_registry_proto::*;

fn _vr_namespace_prefix() -> String {
        let mut sha = Sha512::new();
        sha.input_str("validator-registry");
        sha.result_str()[..6].to_string()
}

fn _to_address(addressable_key: &String) -> String {
    let mut sha = Sha512::new();
    sha.input_str(addressable_key);
    _vr_namespace_prefix() + &sha.result_str()[..64].to_string()
}

fn _as_validatorInfo(validatorInfoStr: String) -> ValidatorInfo {
    let validator_info : ValidatorInfo = serde_json::from_str(&validatorInfoStr).unwrap();
    return validator_info;
}

#[derive(Debug)]
pub struct ValidatorRegistryView {
     state: HashMap<String, Vec<u8>>,
}

impl ValidatorRegistryView {
    fn new(in_state: &HashMap<String, Vec<u8>)  -> ValidatorRegistryView {
        ValidatorRegistryView {
            state: in_state
        }
    }

    pub fn get_validators(&self) -> HashMap<String, ValidatorInfo> {
        let validator_map_addr = _to_address('validator_map');
        let mut result_map : HashMap<String, ValidatorInfo> = HashMap::new();
        for (key, val) in self.state.iter() {
            if key.as_str().starts_with(_vr_namespace_prefix.as_str()) {
                if key != validator_map_addr {
                   result_map.insert(key, value); 
                }
            }
        }

        return result_map;
    }

    pub fn get_validator_info(&self, validator_id: &String) -> ValidatorInfo {
        let validator_id_addr = _to_address(validator_id);
        let state_data = self.state.get(validator_id_addr).unwrap();
        return _as_validatorInfo(state_data);
    }

    pub fn has_validator_info(&self, validator_id: &String) -> bool {
        let validator_id_addr = _to_address(validator_id);
        return self.state.contains_key(validator_id_addr);
    }
}
