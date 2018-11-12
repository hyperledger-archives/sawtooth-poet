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

extern crate openssl;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use crypto::sha2::Sha512;
use protobuf;
use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::messages::setting::{Setting, Setting_Entry};
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;
use sawtooth_sdk::processor::handler::TransactionHandler;
use self::openssl::{hash::MessageDigest, pkey::{PKey, Public}, sha::sha256, sign::Verifier};
use serde_json;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::convert::From;
use std::error;
use std::fmt;
use validator_registry_payload::ValidatorRegistryPayload;
use validator_registry_signup_info::SignupInfoProofData;
use validator_registry_signup_info::ValidatorRegistrySignupInfo;
use validator_registry_validator_info::ValidatorRegistryValidatorInfo;
use validator_registry_validator_map::*;

const SGX_REPORT_DATA_STRUCT_SIZE: usize = 64;

#[derive(Debug, Clone)]
struct ValueError;

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
            namespaces: vec![String::from(get_validator_registry_prefix().to_string())],
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
        let txn_header = &request.header;
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
            ValidatorRegistryPayload::new(request.payload.as_slice(), txn_public_key)
                .expect("Error constructing Validator Registry payload");

        // Create the txn public key's hash
        let mut txn_public_key_hasher = Sha256::new();
        txn_public_key_hasher.input(txn_public_key.as_bytes());
        let txn_public_key_hash = txn_public_key_hasher.result_str();

        let result = self._verify_signup_info(&txn_public_key_hash, &val_reg_payload, context);

        if result.is_ok() {
            let validator_info = ValidatorRegistryValidatorInfo {
                name: val_reg_payload.name.to_owned(),
                id: val_reg_payload.id.to_owned(),
                signup_info: val_reg_payload.get_signup_info().to_owned(),
                txn_id: request.signature.clone(),
            };

            if self._update_validator_state(context,
                                            &val_reg_payload.id,
                                            &val_reg_payload.get_signup_info().anti_sybil_id,
                                            &validator_info).is_err() {
                return Err(ApplyError::InvalidTransaction(
                    String::from("Could not update validator state")));
            }
        } else {
            return Err(ApplyError::InvalidTransaction(String::from("Invalid Signup Info")));
        }

        Ok(())
    }
}

impl ValidatorRegistryTransactionHandler {
    fn _update_validator_state(&self,
                               context: &mut TransactionContext,
                               validator_id: &String,
                               anti_sybil_id: &String,
                               validator_info: &ValidatorRegistryValidatorInfo, )
                               -> Result<(), ValueError> {
        let validator_map_str: String = self._get_validator_map(context);
        let mut validator_map: ValidatorRegistryValidatorMap = serde_json::from_str(&validator_map_str)
            .expect("Error decoding Validator Registry Map string");

        // Clean out old entries in ValidatorInfo and ValidatorMap
        // Protobuf doesn't offer delete item for ValidatorMap so create a new list
        // Use the validator map to find all occurrences of an anti_sybil_id
        // Use any such entry to find the associated validator id.
        // Use that validator id as the key to remove the ValidatorInfo from the
        // registry

        let mut validator_info_address: String;

        for entry_str in validator_map.entries.iter_mut() {
            let mut entry: ValidatorRegistryValidatorMapEntry =
                serde_json::from_str(&entry_str)
                    .expect("Error when reading Validator Registry Map Entry");
            if anti_sybil_id == &entry.key {
                // remove the old validator_info data from state
                validator_info_address = _get_address(&entry.value);
                self._delete_address(context, &validator_info_address);

                // overwrite the old entry with new data
                entry.key = anti_sybil_id.to_string();
                entry.value = validator_id.to_string();
                *entry_str = serde_json::to_string(&entry)
                    .expect("Error converting Validator Registry Map Entry to string").to_string();

                // add the new validator_info to state
                validator_info_address = _get_address(validator_id);
                self._set_data(context, &validator_info_address,
                               &serde_json::to_string(&validator_info)
                                   .expect("Error comverting Validator Registry info to string "));

                break;
            }
        }

        // Add updated state entries to ValidatorMap
        let validator_map_address = _get_address(&String::from("validator_map"));
        self._set_data(context, &validator_map_address,
                       &serde_json::to_string(&validator_map)
                           .expect("Error converting Validator Map to string"));

        info!("Validator id {} was added to the validator_map and set.",
              validator_id);

        Ok(())
    }

    fn _set_data(&self, context: &mut TransactionContext,
                 address: &String,
                 data: &String, ) -> () {
        let mut map: HashMap<String, Vec<u8>> = HashMap::new();
        map.insert(address.to_string(), data.as_bytes().to_vec());
        let addresses = context.set_state(map);
        if addresses.is_err() {
            warn!("Failed to save value at address {}", address);
        }
    }

    fn _verify_signup_info(
        &self,
        originator_public_key_hash: &String,
        val_reg_payload: &ValidatorRegistryPayload,
        context: &mut TransactionContext,
    ) -> Result<(), ValueError> {
        let signup_info: ValidatorRegistrySignupInfo =
            serde_json::from_str(&val_reg_payload.signup_info_str)
                .expect("Error reading Validator Registry Sign-up info from string");
        let proof_data: SignupInfoProofData = serde_json::from_str(&*signup_info.proof_data)
            .expect("Error reading Sign-up info data from string");
        // Verify the attestation verification report signature
        let verification_report = proof_data.verification_report;
        let signature = proof_data.signature;

        // Try to get the report key from the configuration setting.  If it
        // is not there or we cannot parse it, fail verification.
        let report_public_key_pem = self._get_config_setting(
            context,
            &"sawtooth.poet.report_public_key_pem".to_string())
            .expect("Error reading config setting: PoET public key");
        let valid_measurements = self._get_config_setting(
            context,
            &"sawtooth.poet.valid_enclave_measurements".to_string())
            .expect("Error reading config setting: Enclave measurements");
        let valid_basenames = self._get_config_setting(
            context,
            &"sawtooth.poet.valid_enclave_basenames".to_string())
            .expect("Error reading config setting: Enclave basename");

        let public_key = PKey::public_key_from_pem(
            report_public_key_pem
                .expect("Error reading public key information from on-chain setting")
                .as_bytes()
        ).expect("Error creating Public Key object");
        if !verify_message_signature(
            &public_key,
            verification_report.as_bytes(),
            signature.as_bytes(),
        ) {
            error!("Verification report signature does not match");
            return Err(ValueError);
        }

        // Convert verification_report json into HashMap
        let verification_report_tmp_value: serde_json::Value = serde_json::from_str(
            verification_report.as_str()
        ).expect("Error reading verification report as Json");
        let verification_report_dict = verification_report_tmp_value
            .as_object()
            .expect("Error reading verification report as Key Value pair");
        // Verify that the verification report meets the following criteria:
        // Includes an ID field.
        if !verification_report_dict.contains_key("id") {
            error!("Verification report does not contain id field");
            return Err(ValueError);
        }
        // Includes an EPID psuedonym.
        if !verification_report_dict.contains_key("epidPseudonym") {
            error!("Verification report does not contain an EPID psuedonym");
            return Err(ValueError);
        }
        // Verify that the verification report EPID pseudonym matches the anti-sybil ID
        let epid_pseudonym = verification_report_dict.get("epidPseudonym")
            .expect("Error reading epidPseudonym from verification report")
            .as_str()
            .expect("Error converting epidPseudonym as string reference");
        if epid_pseudonym != signup_info.anti_sybil_id {
            error!("The anti-sybil ID in the verification report {} does not match the one \
            contained in the signup information {}", epid_pseudonym, signup_info.anti_sybil_id);
            return Err(ValueError);
        }
        // Includes an enclave quote.
        if !verification_report_dict.contains_key("isvEnclaveQuoteBody") {
            error!("Verification report does not contain enclave quote body");
            return Err(ValueError);
        }
        // The ISV enclave quote body is base 64 encoded
        let enclave_quote = verification_report_dict.get("isvEnclaveQuoteBody")
            .expect("Error reading isvEnclaveQuoteBody from verification report");
        // The report body should be SHA256(SHA256(OPK)|PPK)
        let hash_input = format!("{}{}", originator_public_key_hash.to_uppercase(), signup_info
            .poet_public_key.to_uppercase());
        let hash_value = sha256(hash_input.as_bytes());
        // TODO: Quote verification
        // Verify that the nonce in the verification report matches the nonce in the transaction
        // payload submitted
        let nonce = match verification_report_dict.get("nonce") {
            Some(nonce_present) => nonce_present.as_str()
                .expect("Error reading nonce as string reference"),
            None => "",
        };
        if nonce != signup_info.nonce {
            error!("AVR nonce {} does not match signup info nonce {}", nonce, signup_info.nonce);
            return Err(ValueError);
        }
        Ok(())
    }

    fn _get_setting_data(
        &self,
        context: &mut TransactionContext,
        address: &str,
    ) -> Result<Option<Vec<u8>>, ApplyError> {
        context.get_state(vec![address.to_string()]).map_err(|err| {
            warn!("Internal Error: Failed to load state: {:?}", err);
            ApplyError::InternalError(format!("Failed to load state: {:?}", err))
        })
    }

    fn _get_state(&self, context: &mut TransactionContext,
                  address: &String, ) -> String {
        let entries_ = context.get_state(vec![address.to_string()]); // this return Vec<u8>
        let entries = if entries_.is_ok() {
            entries_.expect("Error reading entries")
        } else {
            warn!("Could not get context for address : {}", address);
            panic!("Error getting context.");
        };

        if entries.is_some() {
            String::from_utf8(entries.expect("Error reading entries"))
                .expect("Error converting entries to string")
        } else {
            panic!("Error getting context.");
        }
    }

    fn _get_validator_map(&self,
                          context: &mut TransactionContext)
                          -> String {
        let address = _get_address(&String::from("validator_map"));
        self._get_state(context, &address)
    }

    fn _delete_address(&self, context: &mut TransactionContext,
                       address: &String, ) -> () {
        let remove_addresses = vec![address.to_string()];
        let addresses = context.delete_state(remove_addresses);

        if addresses.is_ok() && addresses
            .expect("Error reading addresses")
            .is_some() {
            ()
        } else {
            panic!("Error deleting value at address {}.", address.to_string());
        }
    }

    fn _get_config_setting(
        &self,
        context: &mut TransactionContext,
        key: &String, )
        -> Result<Option<String>, ApplyError> {
        let config_key_address = _config_key_to_address(&key);
        let setting_data = self._get_setting_data(context, &config_key_address);

        match setting_data {
            Err(err) => Err(err),
            Ok(entries) => {
                let setting: Setting = unpack_data(&entries.expect("Error reading entries"))?;
                for entry in setting.get_entries().iter() {
                    if entry.get_key() == key {
                        return Ok(Some(entry.get_value().to_string()));
                    }
                }
                Ok(None)
            }
        }
    }
}


fn unpack_data<T>(data: &[u8]) -> Result<T, ApplyError>
    where
        T: protobuf::Message,
{
    protobuf::parse_from_bytes(&data).map_err(|err| {
        warn!(
            "Invalid error: Failed to unmarshal SettingsTransaction: {:?}",
            err
        );
        ApplyError::InternalError(format!(
            "Failed to unmarshal SettingsTransaction: {:?}",
            err
        ))
    })
}

fn _config_short_hash(input_str: String) -> String {
    let _CONFIG_ADDRESS_PART_SIZE: usize = 16;
    let mut hasher = Sha256::new();
    hasher.input(input_str.as_bytes());
    hasher.result_str()[0.._CONFIG_ADDRESS_PART_SIZE].to_string()
}

fn _config_key_to_address(key: &String) -> String {
    let _CONFIG_MAX_KEY_PARTS: usize = 4;
    let _CONFIG_NAMESPACE = "000000".to_string();

    let _CONFIG_ADDRESS_PADDING = _config_short_hash(String::new());

    let key_parts: Vec<&str> = key.split(".").collect();
    if key_parts.len() != (_CONFIG_MAX_KEY_PARTS - 1) {
        panic!("Failed to get key parts");
    }

    let mut addr_parts: Vec<String> = key_parts.iter().map(|key_part| _config_short_hash(key_part.to_string())).collect();
    let addr_parts_len = addr_parts.len();
    for i in 0..(_CONFIG_MAX_KEY_PARTS - addr_parts_len) {
        addr_parts.push(_CONFIG_ADDRESS_PADDING.clone());
    }

    let addr_parts_str: String = addr_parts.into_iter().collect();
    let mut config_address = _CONFIG_NAMESPACE.clone();
    config_address.push_str(&addr_parts_str);
    config_address
}

fn get_validator_registry_prefix() -> String {
    let mut hasher = Sha256::new();
    hasher.input(b"validator_registry");
    hasher.result_str()[0..6].to_string()
}

fn _get_address(key: &String) -> String {
    let mut hasher = Sha256::new();
    hasher.input(&key.to_string().into_bytes());
    get_validator_registry_prefix() + &hasher.result_str()
}

/// Function to verify if message digest (SHA256 of message) is signed using private key
/// associated with the public key sent as a input parameter. Accepts message, public key and
/// signature of the message as input parameters.
///
/// Note: Digest of message is calculated using SHA256 algorithm in this function.
pub fn verify_message_signature(
    pub_key: &PKey<Public>,
    message: &[u8],
    signature: &[u8],
) -> bool {
    let mut verifier = Verifier::new(MessageDigest::sha256(), pub_key)
        .expect("Error creating verifier object for SHA256 algortihm");
    verifier.update(message).expect("Error updating message to verifier");
    verifier.verify(signature).expect("Error verifying message")
}
