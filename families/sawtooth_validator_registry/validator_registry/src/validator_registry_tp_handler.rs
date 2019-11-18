/*
 * Copyright 2019 Intel Corporation.
 * Copyright 2020 Walmart Inc.
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

use crypto::{digest::Digest, sha2::Sha256};
use protos::validator_registry::{
    ValidatorInfo, ValidatorMap, ValidatorMap_Entry, ValidatorRegistryPayload,
};
use sawtooth_sdk::{
    messages::processor::TpProcessRequest,
    processor::handler::{ApplyError, TransactionContext, TransactionHandler},
};
use std::{collections::HashMap, convert::From};
use validator_registry_tp_verifier::verify_signup_info;

const VALIDATOR_MAP_STR: &str = "validator_map";
const VALIDATOR_REGISTRY_STR: &str = "validator_registry";
const VALIDATOR_REGISTRY_VERSION: &str = "2.0";

pub(crate) struct ValidatorRegistryTransactionHandler {
    family_name: String,
    family_versions: Vec<String>,
    namespaces: Vec<String>,
}

impl ValidatorRegistryTransactionHandler {
    pub fn new() -> ValidatorRegistryTransactionHandler {
        ValidatorRegistryTransactionHandler {
            family_name: String::from(VALIDATOR_REGISTRY_STR),
            family_versions: vec![String::from(VALIDATOR_REGISTRY_VERSION)],
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
            parse_from(&request.payload)
                .expect("Error constructing Validator Registry payload");

        // Create the txn public key's hash
        let mut txn_public_key_hasher = Sha256::new();
        txn_public_key_hasher.input(txn_public_key.as_bytes());
        let txn_public_key_hash = txn_public_key_hasher.result_str();

        let result =
            verify_signup_info(context, &txn_public_key_hash, &val_reg_payload);

        match result {
            Ok(_) => {
                let mut validator_info = ValidatorInfo::new();
                validator_info.set_name(val_reg_payload.get_name().to_string());
                validator_info.set_id(val_reg_payload.get_id().to_string());
                validator_info
                    .set_signup_info(val_reg_payload.get_signup_info().clone());
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
            }
            Err(err) => {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Invalid Signup Info {:?}",
                    err
                )));
            }
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
        let mut validator_map = match get_validator_map(context) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        // Clean out old entries in ValidatorInfo and ValidatorMap
        // Use the validator map to find all occurrences of an anti_sybil_id
        // Use any such entry to find the associated validator id.
        // Use that validator id as the key to remove the ValidatorInfo from the
        // registry

        let mut validator_info_address: String;
        for idx in 0..validator_map.entries.len() {
            let entry = validator_map
                .entries
                .get(idx)
                .expect("Unexpected index read");
            if anti_sybil_id == entry.key && !anti_sybil_id.is_empty() {
                // remove the old validator_info data from state
                validator_info_address = get_address(&entry.value);
                if delete_address(context, &validator_info_address).is_err() {
                    return Err(ApplyError::InvalidTransaction(format!(
                        "Error occurred while deleing the address"
                    )));
                }
            }
        }

        let mut entry = ValidatorMap_Entry::new();
        entry.set_key(anti_sybil_id.to_string());
        entry.set_value(validator_id.to_string());
        validator_map.entries.push(entry);

        // Add updated state entries to ValidatorMap
        let validator_map_address =
            get_address(&String::from(VALIDATOR_MAP_STR));
        set_state(context, &validator_map_address, validator_map).map_err(
            |err| {
                ApplyError::InternalError(format!(
                    "Failed to set state at validator map address {:?}",
                    err,
                ))
            },
        )?;

        // add the new validator_info to state
        let validator_info_address = get_address(validator_id);
        info!("{}", validator_info_address.clone());
        set_state(context, &validator_info_address, validator_info.clone())
            .map_err(|err| {
                ApplyError::InternalError(format!(
                    "Failed to set state at validator info address {:?}",
                    err,
                ))
            })?;

        info!(
            "Validator id {} was added to the validator_map and set at address {}.",
            validator_id, validator_info_address
        );

        Ok(())
    }
}

fn get_validator_map(
    context: &mut TransactionContext,
) -> Result<ValidatorMap, ApplyError> {
    let address = get_address(&String::from(VALIDATOR_MAP_STR));
    let state = get_state(context, &address);
    match state {
        Ok(validator_map) => match validator_map {
            None => Ok(ValidatorMap::new()),
            Some(map_data) => parse_from(&map_data),
        },
        Err(e) => Err(e),
    }
}

fn get_validator_registry_prefix() -> String {
    let mut hasher = Sha256::new();
    hasher.input_str(VALIDATOR_REGISTRY_STR);
    hasher.result_str()[0..6].to_string()
}

fn get_address(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.input_str(key);
    get_validator_registry_prefix() + &hasher.result_str()
}

pub(crate) fn set_state<T>(
    context: &mut TransactionContext,
    address: &str,
    data: T,
) -> Result<(), ApplyError>
    where
        T: protobuf::Message,
{
    let bytes = protobuf::Message::write_to_bytes(&data).map_err(|err| {
        ApplyError::InternalError(format!("Failed to serialize: {:?}", err))
    })?;
    let mut map: HashMap<String, Vec<u8>> = HashMap::new();
    map.insert(address.to_string(), bytes);
    context.set_state(map).map_err(|_| {
        warn!("Failed to save value at address {}", address);
        ApplyError::InternalError(format!("Unable to save to state"))
    })?;
    Ok(())
}

pub(crate) fn get_state(
    context: &mut TransactionContext,
    address: &str,
) -> Result<Option<Vec<u8>>, ApplyError> {
    context.get_state(vec![address.to_string()]).map_err(|err| {
        warn!("Internal Error: Failed to load state: {:?}", err);
        ApplyError::InternalError(format!("Failed to load state: {:?}", err))
    })
}

pub(crate) fn delete_address(
    context: &mut TransactionContext,
    address: &str,
) -> Result<(), ApplyError> {
    let remove_addresses = vec![address.to_string()];
    let addresses = context.delete_state(remove_addresses);

    if addresses.is_err()
        || addresses.expect("Error reading addresses").is_none()
    {
        return Err(ApplyError::InternalError(format!(
            "Error deleting value at address {}.",
            address.to_string()
        )));
    }
    Ok(())
}

pub(crate) fn parse_from<T>(data: &[u8]) -> Result<T, ApplyError>
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
