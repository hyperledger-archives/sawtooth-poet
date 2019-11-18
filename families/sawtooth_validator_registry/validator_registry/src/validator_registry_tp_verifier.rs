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

use crate::sgx_structs::{sgx_quote::SgxQuote, SgxStruct};
use crate::validator_registry_tp_handler::{get_state, parse_from};
use base64;
use crypto::{digest::Digest, sha2::Sha256};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Public},
    sha::sha256,
    sign::Verifier,
};
use protos::validator_registry::{SignUpInfo, ValidatorRegistryPayload};
use sawtooth_sdk::{
    messages::setting::Setting,
    processor::handler::{ApplyError, TransactionContext},
};
use std::{iter::repeat, str};

const SETTING_ADDRESS_PART_SIZE: usize = 16;
const SETTING_NAMESPACE: &str = "000000";
const SETTING_MAX_KEY_PARTS: usize = 4;

const SAWTOOTH_POET_REPORT_PUBLIC_KEY_STR: &str =
    "sawtooth.poet.report_public_key_pem";
const SAWTOOTH_POET_VALID_ENCLAVE_MEASUREMENTS: &str =
    "sawtooth.poet.valid_enclave_measurements";
const SAWTOOTH_POET_VALID_ENCLAVE_BASENAMES: &str =
    "sawtooth.poet.valid_enclave_basenames";

pub(crate) fn verify_signup_info(
    context: &mut TransactionContext,
    originator_public_key_hash: &String,
    val_reg_payload: &ValidatorRegistryPayload,
) -> Result<(), ApplyError> {
    let signup_info: SignUpInfo = val_reg_payload.get_signup_info().clone();
    let proof_data = signup_info.get_proof_data().clone();

    // Convert proof_data json into HashMap
    let proof_data_tmp_value: serde_json::Value =
        match serde_json::from_str(proof_data) {
            Ok(proof_data) => proof_data,
            Err(_) => {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Error reading proof data as JSON"
                )))
            }
        };
    let proof_data_dict = match proof_data_tmp_value.as_object() {
        Some(obj) => obj,
        None => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error reading proof data as Key-Value pair"
            )))
        }
    };

    // Verify the attestation verification report signature
    if !proof_data_dict.contains_key("verification_report") {
        error!("Verification report is missing from proof data");
        return Err(ApplyError::InvalidTransaction(format!(
            "Verification report is missing from proof data"
        )));
    }
    let verification_report_data =
        match proof_data_dict.get("verification_report") {
            Some(report) => report,
            None => {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Error reading verification_report from proof data"
                )))
            }
        };
    let verification_report = match verification_report_data.as_str() {
        Some(value) => value,
        None => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error converting verification_report as string reference"
            )))
        }
    };

    if !proof_data_dict.contains_key("signature") {
        error!("Signature is missing from proof data");
        return Err(ApplyError::InvalidTransaction(format!(
            "Signature is missing from proof data"
        )));
    }
    let signature_data = match proof_data_dict.get("signature") {
        Some(signature) => signature,
        None => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error reading signature from proof data"
            )))
        }
    };
    let signature = match signature_data.as_str() {
        Some(value) => value,
        None => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error converting signature as string reference"
            )))
        }
    };

    // Try to get the report key from the configuration setting.  If it
    // is not there or we cannot parse it, fail verification.
    let report_public_key_pem = match get_config_setting(
        context,
        SAWTOOTH_POET_REPORT_PUBLIC_KEY_STR,
    ) {
        Ok(setting) => setting,
        Err(_) => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error reading config setting: IAS report public key"
            )))
        }
    };
    if report_public_key_pem.is_none() {
        return Err(ApplyError::InvalidTransaction(format!(
            "Error reading config setting: IAS report public key"
        )));
    }
    let public_key = match PKey::public_key_from_pem(
        report_public_key_pem.unwrap().as_bytes(),
    ) {
        Ok(key) => key,
        Err(_) => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error creating Public Key object"
            )))
        }
    };

    let decoded_sig = match base64::decode(signature) {
        Ok(sig) => sig,
        Err(_) => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Unable to decode the signature from base64 format"
            )))
        }
    };
    let verified = match verify_message_signature(
        &public_key,
        verification_report.as_bytes(),
        &decoded_sig,
    ) {
        Ok(result) => result,
        Err(e) => return Err(e),
    };
    if !verified {
        error!("Verification report signature does not match");
        return Err(ApplyError::InvalidTransaction(format!(
            "Verification report signature does not match"
        )));
    }

    // Convert verification_report json into HashMap
    let verification_report_tmp_value: serde_json::Value =
        match serde_json::from_str(verification_report) {
            Ok(verification_report) => verification_report,
            Err(_) => {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Error reading verification report as JSON"
                )))
            }
        };
    let verification_report_dict =
        match verification_report_tmp_value.as_object() {
            Some(obj) => obj,
            None => {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Error reading verification report as Key-Value pair"
                )))
            }
        };
    // Verify that the verification report meets the following criteria:
    // Includes an ID field.
    if !verification_report_dict.contains_key("id") {
        error!("Verification report does not contain id field");
        return Err(ApplyError::InvalidTransaction(format!(
            "Verification report does not contain id field"
        )));
    }

    // Includes an EPID psuedonym.
    if !verification_report_dict.contains_key("epidPseudonym") {
        error!("Verification report does not contain an EPID psuedonym");
        return Err(ApplyError::InvalidTransaction(format!(
            "Verification report does not contain an EPID psuedonym"
        )));
    }

    // Verify that the verification report EPID pseudonym matches the anti-sybil ID
    let epid_pseudonym_data =
        match verification_report_dict.get("epidPseudonym") {
            Some(data) => data,
            None => {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Error reading epidPseudonym from verification report"
                )))
            }
        };
    let epid_pseudonym = match epid_pseudonym_data.as_str() {
        Some(value) => value,
        None => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error converting epidPseudonym as string reference"
            )))
        }
    };
    if epid_pseudonym != signup_info.anti_sybil_id {
        error!(
            "The anti-sybil ID in the verification report {} does not match the one \
             contained in the signup information {}",
            epid_pseudonym, signup_info.anti_sybil_id
        );
        return Err(ApplyError::InvalidTransaction(format!(
            "The anti-sybil ID in the verification report {} does not match the one \
             contained in the signup information {}",
            epid_pseudonym, signup_info.anti_sybil_id
        )));
    }

    // Verify that the verification report contains a PSE manifest status
    // and it is OK
    if !verification_report_dict.contains_key("pseManifestStatus") {
        error!("Verification report does not contain a PSE manifest status");
        return Err(ApplyError::InvalidTransaction(format!(
            "Verification report does not contain a PSE manifest status"
        )));
    }
    let pse_manifest_status_data =
        match verification_report_dict.get("pseManifestStatus") {
            Some(status) => status,
            None => {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Error reading pseManifestStatus from verification report"
                )))
            }
        };
    let pse_manifest_status = match pse_manifest_status_data.as_str() {
        Some(value) => value,
        None => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error converting pseManifestStatus as string reference"
            )))
        }
    };
    if pse_manifest_status.to_uppercase() != "OK" {
        if pse_manifest_status.to_uppercase() == "OUT_OF_DATE" {
            warn!("Peer has out of date (but not revoked) hardware, pseManifestStatus: {}", pse_manifest_status);
        } else {
            error!(
                "PSE manifest status is {} (i.e., not OK)",
                pse_manifest_status
            );
            return Err(ApplyError::InvalidTransaction(format!(
                "PSE manifest status is {} (i.e., not OK)",
                pse_manifest_status,
            )));
        }
    }

    // Verify that the verification report contains a PSE manifest hash
    if !verification_report_dict.contains_key("pseManifestHash") {
        error!("Verification report does not contain a PSE manifest hash");
        return Err(ApplyError::InvalidTransaction(format!(
            "Verification report does not contain a PSE manifest hash"
        )));
    }
    let pse_manifest_hash_data =
        match verification_report_dict.get("pseManifestHash") {
            Some(hashed) => hashed,
            None => {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Error reading pseManifestHash from verification report"
                )))
            }
        };
    let pse_manifest_hash = match pse_manifest_hash_data.as_str() {
        Some(value) => value,
        None => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error converting pseManifestHash as string reference"
            )))
        }
    };

    // Verify that the proof data contains evidence payload
    if !proof_data_dict.contains_key("evidence_payload") {
        error!("Evidence payload is missing from proof data");
        return Err(ApplyError::InvalidTransaction(format!(
            "Evidence payload is missing from proof data"
        )));
    }
    let evidence_payload_data = match proof_data_dict.get("evidence_payload") {
        Some(hashed) => hashed,
        None => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error reading evidence_payload from proof data"
            )))
        }
    };
    let evidence_payload = match evidence_payload_data.as_str() {
        Some(value) => value,
        None => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error converting evidence_payload as string reference"
            )))
        }
    };

    // Verify that the evidence payload contains a PSE manifest and then
    // use it to make sure that the PSE manifest hash is what we expect
    let evidence_payload_tmp_value: serde_json::Value =
        match serde_json::from_str(evidence_payload) {
            Ok(evidence_payload) => evidence_payload,
            Err(_) => {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Error reading evidence payload as JSON"
                )))
            }
        };
    let evidence_payload_dict = match evidence_payload_tmp_value.as_object() {
        Some(obj) => obj,
        None => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error reading evidence payload as Key-Value pair"
            )))
        }
    };
    if !evidence_payload_dict.contains_key("pse_manifest") {
        error!("Evidence payload does not include PSE manifest");
        return Err(ApplyError::InvalidTransaction(format!(
            "Evidence payload does not include PSE manifest"
        )));
    }
    let pse_manifest_data = match evidence_payload_dict.get("pse_manifest") {
        Some(pse_manifest) => pse_manifest,
        None => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error reading pse_manifest from evidence payload"
            )))
        }
    };
    let pse_manifest = match pse_manifest_data.as_str() {
        Some(value) => value,
        None => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error converting pse_manifest as string reference"
            )))
        }
    };

    let decoded_pse_manifest = match base64::decode(pse_manifest) {
        Ok(decoded) => decoded,
        Err(_) => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error decoding the PSE manifest"
            )))
        }
    };
    let expected_pse_manifest_hash_string = sha256(&decoded_pse_manifest);
    let expected_pse_manifest_hash =
        to_hex_string(&expected_pse_manifest_hash_string);
    if pse_manifest_hash.to_uppercase()
        != expected_pse_manifest_hash.to_uppercase()
    {
        error!(
            "PSE manifest hash {} does not match {}",
            pse_manifest_hash, expected_pse_manifest_hash
        );
        return Err(ApplyError::InvalidTransaction(format!(
            "PSE manifest hash {} does not match {}",
            pse_manifest_hash, expected_pse_manifest_hash
        )));
    }

    // Includes an enclave quote.
    if !verification_report_dict.contains_key("isvEnclaveQuoteBody") {
        error!("Verification report does not contain enclave quote body");
        return Err(ApplyError::InvalidTransaction(format!(
            "Verification report does not contain enclave quote body"
        )));
    }

    // The ISV enclave quote body is base 64 encoded, decode it
    let enclave_quote_base64 =
        match verification_report_dict.get("isvEnclaveQuoteBody") {
            Some(quote) => quote,
            None => {
                return Err(ApplyError::InvalidTransaction(format!(
                "Error reading isvEnclaveQuoteBody from verification report"
            )))
            }
        };
    let enclave_quote_base64_tmp = match enclave_quote_base64.as_str() {
        Some(value) => value,
        None => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error converting enclaveQuoteBody as string reference"
            )))
        }
    };
    let enclave_quote =
        match base64::decode(enclave_quote_base64_tmp.as_bytes()) {
            Ok(quote) => quote,
            Err(_) => {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Error base64 decoding enclave quote"
                )))
            }
        };
    let mut sgx_quote = SgxQuote::default();
    if sgx_quote.parse_from_bytes(&enclave_quote).is_err() {
        return Err(ApplyError::InvalidTransaction(format!(
            "Error constructing the enclaveQuote structure"
        )));
    }

    // The report body should be SHA256(SHA256(OPK)|PPK)
    let hash_input = format!(
        "{}{}",
        originator_public_key_hash.to_uppercase(),
        signup_info.poet_public_key.to_uppercase()
    );
    let hash_value = sha256(hash_input.as_bytes());
    let mut expected_report_data = Vec::new();
    let length =
        crate::sgx_structs::sgx_report_data::STRUCT_SIZE - hash_value.len();
    let mut filler =
        vec![crate::sgx_structs::sgx_report_data::DEFAULT_VALUE; length];
    expected_report_data.append(&mut hash_value.to_vec());
    expected_report_data.append(&mut filler);

    if &expected_report_data[..]
        == &sgx_quote.report_body().report_data().d()[..]
    {
        return Err(ApplyError::InvalidTransaction(format!(
            "AVR report data {:?} not equal to {:?}",
            &sgx_quote.report_body().report_data().d()[..],
            expected_report_data
        )));
    }

    let valid_measurements_tmp = match get_config_setting(
        context,
        SAWTOOTH_POET_VALID_ENCLAVE_MEASUREMENTS,
    ) {
        Ok(setting) => setting,
        Err(_) => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error reading config setting: Enclave measurements"
            )))
        }
    };
    if valid_measurements_tmp.is_none() {
        return Err(ApplyError::InvalidTransaction(format!(
            "No enclave measurements found"
        )));
    }
    let valid_measurements = valid_measurements_tmp.unwrap();

    let valid_basenames_tmp = match get_config_setting(
        context,
        SAWTOOTH_POET_VALID_ENCLAVE_BASENAMES,
    ) {
        Ok(setting) => setting,
        Err(_) => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error reading config setting: Enclave basenames"
            )))
        }
    };
    if valid_basenames_tmp.is_none() {
        return Err(ApplyError::InvalidTransaction(format!(
            "No enclave basenames found"
        )));
    }
    let valid_basenames = valid_basenames_tmp.unwrap();

    info!("The SGX quote is {:?}", sgx_quote.serialize_to_bytes());

    // if !valid_measurements.into_iter().any(|name| name == measurement) {
    let measurement = to_hex_string(&sgx_quote.report_body().mr_enclave().m());
    if valid_measurements.to_lowercase() != measurement {
        return Err(ApplyError::InvalidTransaction(format!(
            "AVR enclave measurement {} not in the list of valid enclave \
             measurements {:?}",
            measurement, valid_measurements,
        )));
    }

    // Verify that the enclave basename is in the list of valid enclave basenames
    let basename = to_hex_string(&sgx_quote.basename().name());
    // if !valid_basenames.into_iter().any(|name| name == basename) {
    if valid_basenames.to_lowercase() != basename {
        return Err(ApplyError::InvalidTransaction(format!(
            "AVR enclave measurement {} not in the list of valid enclave \
             basenames {:?}",
            basename, valid_basenames,
        )));
    }

    // Verify that the nonce in the verification report matches the nonce in the transaction
    // payload submitted
    let nonce = match verification_report_dict.get("nonce") {
        Some(nonce_present) => match nonce_present.as_str() {
            Some(nonce_str) => nonce_str,
            None => {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Error reading nonce as string reference"
                )))
            }
        },
        None => "",
    };
    if nonce != signup_info.nonce {
        error!(
            "AVR nonce {} does not match signup info nonce {}",
            nonce, signup_info.nonce
        );
        return Err(ApplyError::InvalidTransaction(format!(
            "AVR nonce doesn't match signup info nonce"
        )));
    }
    Ok(())
}

/// Function to verify if message digest (SHA256 of message)
/// is signed using private key associated with the public key
/// sent as a input parameter. Accepts message, public key and
/// signature of the message as input parameters.
///
/// Note: Digest of message is calculated using SHA256 algorithm
/// in this function.
fn verify_message_signature(
    pub_key: &PKey<Public>,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, ApplyError> {
    let mut verifier = match Verifier::new(MessageDigest::sha256(), pub_key) {
        Ok(obj) => obj,
        Err(_) => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error creating verifier object for SHA256 algortihm"
            )))
        }
    };
    if verifier.update(message).is_err() {
        return Err(ApplyError::InvalidTransaction(format!(
            "Error updating message to verifier"
        )));
    }
    match verifier.verify(signature) {
        Err(_) => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Error verifying message"
            )))
        }
        Ok(result) => return Ok(result),
    };
}

fn get_config_setting(
    context: &mut TransactionContext,
    key: &str,
) -> Result<Option<String>, ApplyError> {
    let config_key_address = config_key_to_address(key);
    let setting_data = get_state(context, &config_key_address);

    match setting_data {
        Err(err) => Err(err),
        Ok(entries) => {
            let entries_read = match entries {
                None => {
                    return Err(ApplyError::InvalidTransaction(format!(
                        "Error reading entries"
                    )))
                }
                Some(read) => read,
            };
            let setting: Setting = parse_from(&entries_read)?;
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
    let mut address = String::new();
    address.push_str(SETTING_NAMESPACE);
    address.push_str(
        &key.splitn(SETTING_MAX_KEY_PARTS, '.')
            .chain(repeat(""))
            .map(config_short_hash)
            .take(SETTING_MAX_KEY_PARTS)
            .collect::<Vec<_>>()
            .join(""),
    );

    address
}

fn config_short_hash(input_str: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.input(input_str.as_bytes());
    hasher.result_str()[0..SETTING_ADDRESS_PART_SIZE].to_string()
}

/// Convert from byte array to hex string
pub fn to_hex_string(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
