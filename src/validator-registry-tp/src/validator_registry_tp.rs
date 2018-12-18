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

extern crate base64;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;
use sawtooth_sdk::processor::handler::TransactionHandler;
use serde_json;
use std::collections::HashMap;
use std::convert::From;
use std::error;
use std::fmt;
use validator_registry_payload::ValidatorRegistryPayload;
use validator_registry_tp_verifier::verify_signup_info;
use validator_registry_validator_info::ValidatorRegistryValidatorInfo;
use validator_registry_validator_map::*;

#[derive(Debug, Clone)]
pub struct ValueError;

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid value found")
    }
}

impl error::Error for ValueError {
    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

pub struct ValidatorRegistryTransactionHandler {
    family_name: String,
    family_versions: Vec<String>,
    namespaces: Vec<String>,
}

impl ValidatorRegistryTransactionHandler {
    pub fn new() -> ValidatorRegistryTransactionHandler {
        ValidatorRegistryTransactionHandler {
            family_name: String::from("validator_registry"),
            family_versions: vec![String::from("2.0")],
            namespaces: vec![get_validator_registry_prefix().to_string()],
        }
    }
}

impl TransactionHandler for ValidatorRegistryTransactionHandler {
    fn family_name(&self) -> String {
        self.family_name.clone()
    }

    fn family_versions(&self) -> Vec<String> {
        self.family_versions.clone()
    }

    fn namespaces(&self) -> Vec<String> {
        self.namespaces.clone()
    }

    fn apply(
        &self,
        request: &TpProcessRequest,
        context: &mut TransactionContext,
    ) -> Result<(), ApplyError> {
        // Get txn public key from request header
        let txn_public_key = match &request.header.as_ref() {
            Some(s) => &s.signer_public_key,
            None => {
                return Err(ApplyError::InvalidTransaction(String::from(
                    "Invalid header",
                )));
            }
        };

        // Extract the validator registry payload from txn request payload
        let val_reg_payload: ValidatorRegistryPayload =
            ValidatorRegistryPayload::parse_from(&request.payload, txn_public_key)
                .expect("Error constructing Validator Registry payload");

        // Create the txn public key's hash
        let mut txn_public_key_hasher = Sha256::new();
        txn_public_key_hasher.input(txn_public_key.as_bytes());
        let txn_public_key_hash = txn_public_key_hasher.result_str();

        let result = verify_signup_info(context, &txn_public_key_hash, &val_reg_payload);

        if result.is_ok() {
            let validator_info = ValidatorRegistryValidatorInfo {
                name: val_reg_payload.name.to_owned(),
                id: val_reg_payload.id.to_owned(),
                signup_info: val_reg_payload.get_signup_info().to_owned(),
                txn_id: request.signature.clone(),
            };

            if self
                ._update_validator_state(
                    context,
                    &val_reg_payload.id,
                    &val_reg_payload.get_signup_info().anti_sybil_id,
                    &validator_info,
                )
                .is_err()
            {
                return Err(ApplyError::InvalidTransaction(String::from(
                    "Could not update validator state",
                )));
            }
        } else {
            return Err(ApplyError::InvalidTransaction(String::from(
                "Invalid Signup Info",
            )));
        }

        Ok(())
    }
}

impl ValidatorRegistryTransactionHandler {
    fn _update_validator_state(
        &self,
        context: &mut TransactionContext,
        validator_id: &str,
        anti_sybil_id: &str,
        validator_info: &ValidatorRegistryValidatorInfo,
    ) -> Result<(), ValueError> {
        let mut validator_map = self._get_validator_map(context);

        // Clean out old entries in ValidatorInfo and ValidatorMap
        // Use the validator map to find all occurrences of an anti_sybil_id
        // Use any such entry to find the associated validator id.
        // Use that validator id as the key to remove the ValidatorInfo from the
        // registry

        let mut validator_info_address: String;
        for idx in 0..validator_map.entries.len() {
            let mut entry_str = validator_map
                .entries
                .get_mut(idx)
                .expect("Unexpected index read");
            let mut entry: ValidatorRegistryValidatorMapEntry = serde_json::from_str(&entry_str)
                .expect("Error when reading Validator Registry Map Entry");
            if anti_sybil_id == entry.key && !anti_sybil_id.is_empty() {
                // remove the old validator_info data from state
                validator_info_address = _get_address(&entry.value);
                self._delete_address(context, &validator_info_address);
            }
        }

        let entry = ValidatorRegistryValidatorMapEntry {
            key: anti_sybil_id.to_string(),
            value: validator_id.to_string(),
        };
        let entry_str = serde_json::to_string(&entry)
            .expect("Error converting Validator Registry Map Entry to string");
        validator_map.entries.push(entry_str);

        // Add updated state entries to ValidatorMap
        let validator_map_address = _get_address(&String::from("validator_map"));
        self._set_data(
            context,
            &validator_map_address,
            &serde_json::to_string(&validator_map)
                .expect("Error converting Validator Map to string"),
        );

        // add the new validator_info to state
        let validator_info_address = _get_address(validator_id);
        info!("{}", validator_info_address.clone());
        self._set_data(
            context,
            &validator_info_address,
            &serde_json::to_string(&validator_info)
                .expect("Error comverting Validator Registry info to string "),
        );

        info!(
            "Validator id {} was added to the validator_map and set at address {}.",
            validator_id, validator_info_address
        );

        Ok(())
    }

    fn _set_data(&self, context: &mut TransactionContext, address: &str, data: &str) {
        let mut map: HashMap<String, Vec<u8>> = HashMap::new();
        map.insert(address.to_string(), data.as_bytes().to_vec());
        let addresses = context.set_state(map);
        if addresses.is_err() {
            warn!("Failed to save value at address {}", address);
        }
    }

    fn _get_state(
        &self,
        context: &mut TransactionContext,
        address: &str,
    ) -> Result<String, String> {
        let entries_ = context.get_state(vec![address.to_string()]); // this return Option<Vec<u8>>
        let entries = if entries_.is_ok() {
            entries_.expect("Error reading entries")
        } else {
            warn!("Could not get context for address : {}", address);
            return Err("Error getting context.".to_string());
        };

        match entries {
            Some(present) => {
                Ok(String::from_utf8(present).expect("Error converting entries to string"))
            }
            None => Err("Error getting context.".to_string()),
        }
    }

    fn _get_validator_map(
        &self,
        context: &mut TransactionContext,
    ) -> ValidatorRegistryValidatorMap {
        let address = _get_address(&String::from("validator_map"));
        let state = self._get_state(context, &address);
        let to_return = match state {
            Ok(validator_map_str) => {
                let mut validator_map: ValidatorRegistryValidatorMap =
                    serde_json::from_str(&validator_map_str)
                        .expect("Error decoding Validator Registry Map string");
                validator_map
            }
            Err(error) => {
                error!("Error in _get_validator_map {}", error);
                ValidatorRegistryValidatorMap::default()
            }
        };
        info!("Validator Map {:?}", to_return);
        to_return
    }

    fn _delete_address(&self, context: &mut TransactionContext, address: &str) {
        let remove_addresses = vec![address.to_string()];
        let addresses = context.delete_state(remove_addresses);

        if addresses.is_err() || addresses.expect("Error reading addresses").is_none() {
            panic!("Error deleting value at address {}.", address.to_string());
        }
    }
}

fn get_validator_registry_prefix() -> String {
    let mut hasher = Sha256::new();
    hasher.input_str("validator_registry");
    hasher.result_str()[0..6].to_string()
}

fn _get_address(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.input_str(&key.to_string().as_str());
    get_validator_registry_prefix() + &hasher.result_str()
}
