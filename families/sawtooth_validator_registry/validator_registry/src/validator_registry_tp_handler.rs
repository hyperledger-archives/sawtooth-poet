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
use std::collections::HashMap;
use std::convert::From;

use protobuf::RepeatedField;
use protos::validator_registry::{
    ValidatorInfo, ValidatorMap, ValidatorMap_Entry, ValidatorRegistryPayload,
};

use validator_registry_tp_verifier::verify_signup_info;

const VALIDATOR_MAP_STR: &str = "validator_map";
const VALIDATOR_REGISTRY_STR: &str = "validator_registry";

pub fn parse_from<T>(data: &[u8]) -> Result<T, ApplyError>
where
    T: protobuf::Message,
{
    protobuf::parse_from_bytes(&data).map_err(|err| {
        warn!(
            "Invalid error: Failed to parse ValidatorRegistryTransaction: {:?}",
            err
        );
        ApplyError::InternalError(format!(
            "Failed to unmarshal ValidatorRegistryTransaction: {:?}",
            err
        ))
    })
}

fn set_state<T>(context: &mut TransactionContext, address: &str, data: T) -> Result<(), ApplyError>
where
    T: protobuf::Message,
{
    let bytes = protobuf::Message::write_to_bytes(&data)
        .map_err(|err| ApplyError::InternalError(format!("Failed to serialize: {:?}", err)))?;
    let mut map: HashMap<String, Vec<u8>> = HashMap::new();
    map.insert(address.to_string(), bytes);
    context.set_state(map).map_err(|_| {
        warn!("Failed to save value at address {}", address);
        ApplyError::InternalError("Unable to save to state".to_string())
    })?;
    Ok(())
}

pub fn get_state(
    context: &mut TransactionContext,
    address: &str,
) -> Result<Option<Vec<u8>>, ApplyError> {
    context.get_state(vec![address.to_string()]).map_err(|err| {
        warn!("Internal Error: Failed to load state: {:?}", err);
        ApplyError::InternalError(format!("Failed to load state: {:?}", err))
    })
}

pub struct ValidatorRegistryTransactionHandler {
    family_name: String,
    family_versions: Vec<String>,
    namespaces: Vec<String>,
}

impl ValidatorRegistryTransactionHandler {
    pub fn new() -> ValidatorRegistryTransactionHandler {
        ValidatorRegistryTransactionHandler {
            family_name: String::from(VALIDATOR_REGISTRY_STR),
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
                    "Invalid transaction header",
                )));
            }
        };

        // Extract the validator registry payload from txn request payload
        let val_reg_payload: ValidatorRegistryPayload =
            parse_from(&request.payload).expect("Error constructing Validator Registry payload");

        // Create the txn public key's hash
        let mut txn_public_key_hasher = Sha256::new();
        txn_public_key_hasher.input(txn_public_key.as_bytes());
        let txn_public_key_hash = txn_public_key_hasher.result_str();

        let result = verify_signup_info(context, &txn_public_key_hash, &val_reg_payload);

        if result.is_ok() {
            let mut validator_info = ValidatorInfo::new();
            validator_info.set_name(val_reg_payload.get_name().to_string().clone());
            validator_info.set_id(val_reg_payload.get_id().to_string().clone());
            validator_info.set_signup_info(val_reg_payload.get_signup_info().to_owned());
            validator_info.set_transaction_id(request.signature.clone());

            if self
                .update_validator_state(
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
    fn update_validator_state(
        &self,
        context: &mut TransactionContext,
        validator_id: &str,
        anti_sybil_id: &str,
        validator_info: &ValidatorInfo,
    ) -> Result<(), ApplyError> {
        let validator_map = match self.get_validator_map(context) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        // Clean out old entries in ValidatorInfo and ValidatorMap
        // Use the validator map to find all occurrences of an anti_sybil_id
        // Use any such entry to find the associated validator id.
        // Use that validator id as the key to remove the ValidatorInfo from the
        // registry

        let mut validator_info_address: String;
        let entries = validator_map.get_entries().to_vec();
        let mut updated_entries: Vec<ValidatorMap_Entry> = Vec::new();
        for id in 0..entries.len() {
            let entry = entries.get(id).expect("Unexpected index read");
            if anti_sybil_id == entry.get_key() && !anti_sybil_id.is_empty() {
                // remove the old validator_info data from state
                validator_info_address = get_address(&entry.get_value());
                self.delete_address(context, &validator_info_address);
            } else {
                updated_entries.push(entry.clone());
            }
        }

        let mut updated_entry = ValidatorMap_Entry::new();
        updated_entry.set_key(anti_sybil_id.to_string());
        updated_entry.set_value(validator_id.to_string());
        updated_entries.push(updated_entry);

        let updated_entries_as_bytes: RepeatedField<ValidatorMap_Entry> =
            RepeatedField::from_vec(updated_entries);
        let mut updated_validator_map: ValidatorMap = ValidatorMap::new();
        updated_validator_map.set_entries(updated_entries_as_bytes);

        let validator_map_address = get_address(VALIDATOR_MAP_STR);
        set_state(context, &validator_map_address, updated_validator_map).map_err(|err| {
            ApplyError::InternalError(format!(
                "Failed to set state at validator map address {:?}",
                err
            ))
        })?;

        // add the new validator_info to state
        let validator_info_address = get_address(validator_id);
        info!("{}", validator_info_address.clone());
        set_state(context, &validator_info_address, validator_info.clone()).map_err(|err| {
            ApplyError::InternalError(format!(
                "Failed to set state at validator info address {:?}",
                err
            ))
        })?;

        info!(
            "Validator id {} was added to the validator_map and set at address {}.",
            validator_id, validator_info_address
        );

        Ok(())
    }

    fn get_validator_map(
        &self,
        context: &mut TransactionContext,
    ) -> Result<ValidatorMap, ApplyError> {
        let address = get_address(VALIDATOR_MAP_STR);
        let state = get_state(context, &address);
        match state {
            Err(e) => Err(e),
            Ok(v) => match v {
                None => Ok(ValidatorMap::new()),
                Some(x) => parse_from(&x),
            },
        }
    }

    fn delete_address(&self, context: &mut TransactionContext, address: &str) {
        let remove_addresses = vec![address.to_string()];
        let addresses = context.delete_state(remove_addresses);

        if addresses.is_err() || addresses.expect("Error reading addresses").is_none() {
            panic!("Error deleting value at address {}.", address.to_string());
        }
    }
}

fn get_validator_registry_prefix() -> String {
    let mut hasher = Sha256::new();
    hasher.input_str(VALIDATOR_REGISTRY_STR);
    hasher.result_str()[0..6].to_string()
}

fn get_address(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.input_str(&key.to_string().as_str());
    get_validator_registry_prefix() + &hasher.result_str()
}
