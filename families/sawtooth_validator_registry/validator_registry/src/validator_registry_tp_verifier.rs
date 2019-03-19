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

use self::openssl::{
    hash::MessageDigest,
    pkey::{PKey, Public},
    sha::sha256,
    sign::Verifier,
};
use crypto::{digest::Digest, sha2::Sha256};
use protos::validator_registry::{SignUpInfo, SignUpInfoProof, ValidatorRegistryPayload};
use sawtooth_sdk::{
    messages::setting::Setting,
    processor::handler::{ApplyError, TransactionContext},
};

use validator_registry_tp_handler::{get_state, parse_from};

const _CONFIG_ADDRESS_PART_SIZE: usize = 16;
const _CONFIG_NAMESPACE: &str = "000000";
const _CONFIG_MAX_KEY_PARTS: usize = 4;

pub fn verify_signup_info(
    context: &mut TransactionContext,
    originator_public_key_hash: &str,
    val_reg_payload: &ValidatorRegistryPayload,
) -> Result<(), ApplyError> {
    let signup_info: SignUpInfo = val_reg_payload.get_signup_info().clone();
    let proof_data: SignUpInfoProof = signup_info.get_proof_data().clone();

    // Verify the attestation verification report signature
    let verification_report = proof_data.get_verification_report();
    let signature = &proof_data.get_signature();

    // Try to get the report key from the configuration setting.  If it
    // is not there or we cannot parse it, fail verification.
    let report_public_key_pem =
        get_config_setting(context, &"sawtooth.poet.report_public_key_pem".to_string())
            .expect("Error reading config setting: PoET public key");

    let public_key = PKey::public_key_from_pem(
        report_public_key_pem
            .expect("Error reading public key information from on-chain setting")
            .as_bytes(),
    )
    .expect("Error creating Public Key object");
    let decoded_sig = base64::decode(signature).unwrap();
    if !verify_message_signature(&public_key, verification_report.as_bytes(), &decoded_sig) {
        error!("Verification report signature does not match");
        return Err(ApplyError::InternalError(
            "Verification report signature does not match".to_string(),
        ));
    }

    // Convert verification_report json into HashMap
    let verification_report_tmp_value: serde_json::Value =
        serde_json::from_str(verification_report)
            .expect("Error reading verification report as Json");
    let verification_report_dict = verification_report_tmp_value
        .as_object()
        .expect("Error reading verification report as Key Value pair");
    // Verify that the verification report meets the following criteria:
    // Includes an ID field.
    if !verification_report_dict.contains_key("id") {
        error!("Verification report does not contain id field");
        return Err(ApplyError::InternalError(
            "Verification report does not contain id field".to_string(),
        ));
    }
    // Includes an EPID psuedonym.
    if !verification_report_dict.contains_key("epidPseudonym") {
        error!("Verification report does not contain an EPID psuedonym");
        return Err(ApplyError::InternalError(
            "Verification report does not contain an EPID psuedonym".to_string(),
        ));
    }
    // Verify that the verification report EPID pseudonym matches the anti-sybil ID
    let epid_pseudonym = verification_report_dict
        .get("epidPseudonym")
        .expect("Error reading epidPseudonym from verification report")
        .as_str()
        .expect("Error converting epidPseudonym as string reference");
    if epid_pseudonym != signup_info.anti_sybil_id {
        error!(
            "The anti-sybil ID in the verification report {} does not match the one \
             contained in the signup information {}",
            epid_pseudonym, signup_info.anti_sybil_id
        );
        return Err(ApplyError::InternalError(
            "The anti-sybil ID in the verification report does not match in \
             the signup information"
                .to_string(),
        ));
    }
    // Includes an enclave quote.
    if !verification_report_dict.contains_key("isvEnclaveQuoteBody") {
        error!("Verification report does not contain enclave quote body");
        return Err(ApplyError::InternalError(
            "Verification report does not contain enclave quote body".to_string(),
        ));
    }
    // The ISV enclave quote body is base 64 encoded
    let _enclave_quote = verification_report_dict
        .get("isvEnclaveQuoteBody")
        .expect("Error reading isvEnclaveQuoteBody from verification report");
    // The report body should be SHA256(SHA256(OPK)|PPK)
    let hash_input = format!(
        "{}{}",
        originator_public_key_hash.to_uppercase(),
        signup_info.poet_public_key.to_uppercase()
    );
    let _hash_value = sha256(hash_input.as_bytes());
    // TODO: Quote verification
    // Verify that the nonce in the verification report matches the nonce in the transaction
    // payload submitted
    let nonce = match verification_report_dict.get("nonce") {
        Some(nonce_present) => nonce_present
            .as_str()
            .expect("Error reading nonce as string reference"),
        None => "",
    };
    if nonce != signup_info.nonce {
        error!(
            "AVR nonce {} does not match signup info nonce {}",
            nonce, signup_info.nonce
        );
        return Err(ApplyError::InternalError(
            "AVR nonce doesn't match signup info nonce".to_string(),
        ));
    }
    Ok(())
}

/// Function to verify if message digest (SHA256 of message) is signed using private key
/// associated with the public key sent as a input parameter. Accepts message, public key and
/// signature of the message as input parameters.
///
/// Note: Digest of message is calculated using SHA256 algorithm in this function.
fn verify_message_signature(pub_key: &PKey<Public>, message: &[u8], signature: &[u8]) -> bool {
    let mut verifier = Verifier::new(MessageDigest::sha256(), pub_key)
        .expect("Error creating verifier object for SHA256 algortihm");
    verifier
        .update(message)
        .expect("Error updating message to verifier");
    verifier.verify(signature).expect("Error verifying message")
}

fn get_config_setting(
    context: &mut TransactionContext,
    key: &str,
) -> Result<Option<String>, ApplyError> {
    let config_key_address = config_key_to_address(&key);
    let setting_data = get_state(context, &config_key_address);

    match setting_data {
        Err(err) => Err(err),
        Ok(entries) => {
            let setting: Setting = parse_from(&entries.expect("Error reading entries"))?;
            for entry in setting.get_entries().iter() {
                if entry.get_key() == key {
                    return Ok(Some(entry.get_value().to_string()));
                }
            }
            Ok(None)
        }
    }
}

fn config_key_to_address(key: &str) -> String {
    let _config_address_padding = config_short_hash(String::new());

    let key_parts: Vec<&str> = key.split('.').collect();
    if key_parts.len() != (_CONFIG_MAX_KEY_PARTS - 1) {
        panic!("Failed to get key parts");
    }

    let mut addr_parts: Vec<String> = key_parts
        .iter()
        .map(|key_part| config_short_hash(key_part.to_string()))
        .collect();
    let addr_parts_len = addr_parts.len();
    for _i in 0..(_CONFIG_MAX_KEY_PARTS - addr_parts_len) {
        addr_parts.push(_config_address_padding.clone());
    }

    let addr_parts_str: String = addr_parts.into_iter().collect();
    let mut config_address = _CONFIG_NAMESPACE.to_string();
    config_address.push_str(&addr_parts_str);
    config_address
}

fn config_short_hash(input_str: String) -> String {
    let mut hasher = Sha256::new();
    hasher.input(input_str.as_bytes());
    hasher.result_str()[0.._CONFIG_ADDRESS_PART_SIZE].to_string()
}
