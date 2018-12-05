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
 * ------------------------------------------------------------------------------
 */

extern crate openssl;
extern crate base64;

use ias_client::{client_utils::read_body_as_string, ias_client::IasClient};
use openssl::pkey::PKey;
use poet2_util;
use poet2_util::{read_binary_file, read_file_as_string, verify_message_signature};
use poet_config::PoetConfig;
use serde_json::{from_str, Value};
use serde_json;
use sgxffi::ffi;
use sgxffi::ffi::r_sgx_enclave_id_t;
use sgxffi::ffi::r_sgx_epid_group_t;
use sgxffi::ffi::r_sgx_signup_info_t;
use sgxffi::ffi::r_sgx_wait_certificate_t;
use std::env;
use std::os::raw::c_char;
use std::path::Path;
use std::path::PathBuf;
use std::str;
use std::string::String;
use std::vec::Vec;
use validator_registry_tp::validator_registry_signup_info::{SignupInfoProofData,
                                                            ValidatorRegistrySignupInfo};

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct WaitCertificate {
    pub duration_id: String,
    pub prev_wait_cert_sig: String,
    pub prev_block_id: String,
    pub block_summary: String,
    pub block_number: u64,
    pub validator_id: String,
    pub wait_time: u64,
}

impl Default for WaitCertificate {
    fn default() -> WaitCertificate {
        WaitCertificate {
            duration_id: String::new(),
            prev_wait_cert_sig: String::new(),
            prev_block_id: String::new(),
            block_summary: String::new(),
            block_number: 0_u64,
            validator_id: String::new(),
            wait_time: 0_u64, // May be deprecated in later versions
        }
    }
}

pub struct EnclaveConfig {
    pub enclave_id: r_sgx_enclave_id_t,
    pub signup_info: r_sgx_signup_info_t,
    ias_client: IasClient,
}

const DEFAULT_IAS_REPORT_KEY_FILE: &str = "src/resources/ias_report_key.pem";
const IAS_REPORT_SIGNATURE: &str = "x-iasreport-signature";

impl EnclaveConfig {
    pub fn default() -> Self {
        let enclave_id = r_sgx_enclave_id_t {
            handle: 0,
            mr_enclave: 0 as *mut c_char,
            basename: 0 as *mut c_char,
        };
        let signup_info = r_sgx_signup_info_t {
            handle: 0,
            poet_public_key: 0 as *mut c_char,
            poet_public_key_len: 0,
            enclave_quote: 0 as *mut c_char, //Used for IAS operations
        };

        EnclaveConfig {
            enclave_id,
            signup_info,
            ias_client: IasClient::default(),
        }
    }

    pub fn initialize_enclave(
        &mut self,
        config: &PoetConfig,
    ) {
        let mut eid: r_sgx_enclave_id_t = r_sgx_enclave_id_t {
            handle: 0,
            mr_enclave: 0 as *mut c_char,
            basename: 0 as *mut c_char,
        };

        // Always fetch SPID from config file, dummy values are accepted when running in
        // simulator mode.
        let spid_str = config.get_spid();

        let mut lib_path = env::current_dir().unwrap();
        lib_path.push("../build/bin/libpoet_enclave.signed.so");
        if !Path::new(&lib_path).exists() {
            lib_path = PathBuf::from("/usr/lib/libpoet_enclave.signed.so");
            if !Path::new(&lib_path).exists() {
                panic!("There is missing libpoet_enclave.signed.so");
            }
        }

        let bin_path = &lib_path.into_os_string().into_string().unwrap();

        ffi::init_enclave(&mut eid, bin_path, spid_str.as_str())
            .expect("Failed to initialize enclave");
        info!("Initialized enclave");

        self.enclave_id.handle = eid.handle;
        self.enclave_id.basename = eid.basename;
        self.enclave_id.mr_enclave = eid.mr_enclave;
    }

    /// Initialization if running on SGX hardware. Fill up IAS client object parameters from
    /// config file.
    pub fn initialize_remote_attestation(
        &mut self,
        config: &PoetConfig,
    ) {
        if self.check_if_sgx_simulator() == false {
            self.ias_client.set_ias_url(config.get_ias_url());
            self.ias_client.set_spid_cert(read_binary_file(config.get_spid_cert_file().as_str()));
            self.ias_client.set_password(config.get_password());
            self.update_sig_rl();
        }
    }

    pub fn create_signup_info(
        &mut self,
        pub_key_hash: &Vec<u8>,
        nonce: String,
        config: &PoetConfig,
    ) -> ValidatorRegistrySignupInfo {

        // Update SigRL before getting quote
        self.update_sig_rl();
        let mut eid: r_sgx_enclave_id_t = self.enclave_id;
        let mut signup: r_sgx_signup_info_t = self.signup_info;
        info!("creating signup_info");

        ffi::create_signup_info(&mut eid,
                                &(poet2_util::to_hex_string(&pub_key_hash.to_vec())),
                                &mut signup).expect("Failed to create signup info");

        self.signup_info.handle = signup.handle;
        self.signup_info.poet_public_key = signup.poet_public_key;
        self.signup_info.poet_public_key_len = signup.poet_public_key_len;
        self.signup_info.enclave_quote = signup.enclave_quote;

        let (poet_public_key, quote) = self.get_signup_parameters();
        let mut proof_data_string = String::new();
        let mut epid_pseudonym = String::new();
        if self.check_if_sgx_simulator() == false {
            let raw_response = self.ias_client.post_verify_attestation(
                quote.as_ref(),
                None,
                Option::from(nonce.as_str()),
            ).expect("Error getting AVR");
            // Response body is the AVR or Verification Report
            let verification_report = read_body_as_string(raw_response.body)
                .expect("Error reading the response body");
            let signature = raw_response.header_map.get(IAS_REPORT_SIGNATURE)
                .expect("Error reading IAS signature in response")
                .to_str()
                .expect("Error reading IAS signature header value as string")
                .to_string();
            let proof_data_struct = SignupInfoProofData {
                verification_report,
                signature,
            };

            // Verify AVR
            check_verification_report(
                &proof_data_struct,
                config,
            ).expect("Invalid attestation report");
            debug!("Verification successful!");

            proof_data_string = serde_json::to_string(&proof_data_struct)
                .expect("Error serializing structure to string");

            // Fill up signup information from AVR
            let verification_report_tmp_dict: Value = from_str(
                proof_data_struct.verification_report.as_str()
            ).expect("Error deserializing verification report");
            let verification_report_dict = verification_report_tmp_dict.as_object()
                .expect("Error reading verification report as hashmap");
            epid_pseudonym = verification_report_dict.get("epidPseudonym")
                .expect("No EPID Pseudonym in AVR")
                .as_str()
                .expect("Error reading EPID pseudonym as string")
                .to_string();
        }
        ValidatorRegistrySignupInfo::new(
            poet_public_key,
            proof_data_string,
            epid_pseudonym,
            nonce,
        )
    }

    pub fn initialize_wait_certificate(
        eid: r_sgx_enclave_id_t,
        in_prev_wait_cert: String,
        in_prev_wait_cert_sig: String,
        in_validator_id: &Vec<u8>,
        in_poet_pub_key: &String,
    ) -> u64 { // duration
        let mut duration: u64 = 0_u64;
        let mut eid: r_sgx_enclave_id_t = eid;
        // initialize wait certificate - to get duration from enclave
        ffi::initialize_wait_cert(&mut eid, &mut duration,
                                  &in_prev_wait_cert, &in_prev_wait_cert_sig,
                                  &poet2_util::to_hex_string(&in_validator_id.to_vec()),
                                  &in_poet_pub_key)
            .expect("Failed to initialize Wait certificate");

        debug!("Duration fetched from enclave = {:x?}", duration);

        duration
    }

    pub fn finalize_wait_certificate(
        eid: r_sgx_enclave_id_t,
        in_wait_cert: String,
        in_prev_block_id: String,
        in_prev_wait_cert_sig: String,
        in_block_summary: String,
        in_wait_time: u64,
    ) -> (String, String) {
        let mut eid: r_sgx_enclave_id_t = eid;

        let mut wait_cert_info: r_sgx_wait_certificate_t
        = r_sgx_wait_certificate_t {
            handle: 0,
            ser_wait_cert: 0 as *mut c_char,
            ser_wait_cert_sign: 0 as *mut c_char,
        };

        ffi::finalize_wait_cert(
            &mut eid,
            &mut wait_cert_info,
            &in_wait_cert, &in_prev_block_id,
            &in_prev_wait_cert_sig,
            &in_block_summary, &in_wait_time,
        ).expect("Failed to finalize Wait certificate");

        let wait_cert = ffi::create_string_from_char_ptr(
            wait_cert_info.ser_wait_cert as *mut c_char);

        let wait_cert_sign = ffi::create_string_from_char_ptr(
            wait_cert_info.ser_wait_cert_sign as *mut c_char);

        info!("wait certificate generated is {:?}", wait_cert);

        //release wait certificate
        ffi::release_wait_certificate(&mut eid, &mut wait_cert_info)
            .expect("Failed to release wait certificate");

        (wait_cert, wait_cert_sign)
    }

    pub fn verify_wait_certificate(
        eid: r_sgx_enclave_id_t,
        poet_pub_key: &String,
        wait_cert: &String,
        wait_cert_sign: &String,
    ) -> bool {
        let mut eid: r_sgx_enclave_id_t = eid;
        let mut verify_wait_cert_status: bool = false;
        ffi::verify_wait_certificate(
            &mut eid,
            &wait_cert.as_str(),
            &wait_cert_sign.as_str(),
            &poet_pub_key.as_str(),
            &mut verify_wait_cert_status,
        ).expect("Failed to verify wait certificate");
        verify_wait_cert_status
    }

    pub fn get_epid_group(
        &mut self
    ) -> String {
        let mut eid: r_sgx_enclave_id_t = self.enclave_id;
        let mut epid_info: r_sgx_epid_group_t = r_sgx_epid_group_t {
            epid: 0 as *mut c_char
        };
        ffi::get_epid_group(&mut eid, &mut epid_info)
            .expect("Failed to get EPID group");
        let epid = ffi::create_string_from_char_ptr(epid_info.epid);
        debug!("EPID group = {:?}", epid);
        epid
    }

    /// Returns boolean, information if POET is run in hardware or simulator mode.
    pub fn check_if_sgx_simulator(
        &mut self
    ) -> bool {
        let mut eid: r_sgx_enclave_id_t = self.enclave_id;
        let mut sgx_simulator: bool = false;
        ffi::is_sgx_simulator(&mut eid, &mut sgx_simulator)
            .expect("Failed to check SGX simulator");
        debug!("is_sgx_simulator ? {:?}", if sgx_simulator { "Yes" } else { "No" });
        sgx_simulator
    }

    pub fn set_sig_revocation_list(
        &mut self,
        sig_rev_list: &String,
    ) {
        let mut eid: r_sgx_enclave_id_t = self.enclave_id;
        ffi::set_sig_revocation_list(&mut eid, &sig_rev_list.as_str())
            .expect("Failed to set sig revocation list");
        debug!("Signature revocation list has been updated");
    }

    pub fn get_signup_parameters(
        &mut self
    ) -> (String, String) {
        let signup_data: r_sgx_signup_info_t = self.signup_info;
        let poet_pub_key = ffi::create_string_from_char_ptr(
            signup_data.poet_public_key as *mut c_char);
        let enclave_quote = ffi::create_string_from_char_ptr(
            signup_data.enclave_quote as *mut c_char);
        (poet_pub_key, enclave_quote)
    }

    /// Method to update signature revocation list received from IAS. Pass it to enclave. Note
    /// that this method is applicable only when PoET is run in SGX hardware mode.
    pub fn update_sig_rl(
        &mut self
    ) {
	//TODO - Change SGX API to get EPID group ID and uncomment the below
	/*
        if self.check_if_sgx_simulator() == false {
            let epid_group = self.get_epid_group();
            let sig_rl_response =
                self.ias_client.get_signature_revocation_list(
                    Option::from(epid_group.as_str()),
                    None,
                ).expect("Error fetching SigRL");
            let sig_rl_string = read_body_as_string(sig_rl_response.body)
                .expect("Error reading SigRL response as string");
            debug!("Received SigRl of {} length", sig_rl_string.len());
            self.set_sig_revocation_list(&sig_rl_string)
        }
	*/
    }
}

/// Function to verify if specified verification report is valid. Performs signature verification
/// along with other checks for presence of id, epid pseudonym, revocation reason, ISV enclave
/// quote, nonce.
fn check_verification_report(
    proof_data: &SignupInfoProofData,
    config: &PoetConfig,
) -> Result<(), ()> {
    let verification_report = &proof_data.verification_report;
    let signature = &proof_data.signature;
    // First thing we will do is verify the signature over the verification report. The signature
    // over the verification report uses RSA-SHA256.
    let mut ias_report_key_file = config.get_ias_report_key_file();
    if ias_report_key_file.len() == 0 {
        ias_report_key_file = DEFAULT_IAS_REPORT_KEY_FILE.to_string();
    }
    let ias_report_key_contents = read_file_as_string(ias_report_key_file.as_str());
    let public_key = PKey::public_key_from_pem(ias_report_key_contents.as_bytes())
        .expect("Error reading IAS report key");

    let decoded_sig = base64::decode(signature).unwrap();
    if !verify_message_signature(
        &public_key,
        verification_report.as_bytes(),
        &decoded_sig,
    ) {
        error!("Verification report signature does not match");
        return Err(());
    }

    // Convert verification_report json into HashMap
    let verification_report_tmp_value: Value = from_str(verification_report)
        .expect("Error in json deserializing verification report");
    let verification_report_dict = verification_report_tmp_value.as_object()
        .expect("Error reading deserialized json as key value pair");
    // Verify that the verification report meets the following criteria:
    // 1. Includes an ID field.
    if !verification_report_dict.contains_key("id") {
        error!("AVR does not contain id field");
        return Err(());
    }
    // 2. Does not include a revocation reason.
    if verification_report_dict.contains_key("revocationReason") {
        error!("AVR indicates the EPID group has been revoked");
        return Err(());
    }
    // 3. Includes an enclave quote status
    let enclave_status = verification_report_dict.get("isvEnclaveQuoteStatus");
    if !enclave_status.is_some() {
        error!("AVR does not include an enclave quote status");
        return Err(());
    }
    // 4. Enclave quote status should be "OK".
    let enclave_quote_status = enclave_status.unwrap().as_str()
        .expect("Error reading quote status as string");
    if enclave_quote_status.to_uppercase() != "OK" {
        // Allow out of date severity issues to pass.
        if enclave_quote_status.to_uppercase() != "GROUP_OUT_OF_DATE" {
            error!("Machine requires update (probably BIOS) for SGX compliance.");
        } else {
            error!("AVR enclave quote status is bad: {}", enclave_quote_status);
            return Err(());
        }
    }
    // 5. Includes an enclave quote.
    if !verification_report_dict.contains_key("isvEnclaveQuoteBody") {
        error!("AVR does not contain quote body");
        return Err(());
    }
    // 6. Includes an EPID psuedonym.
    if !verification_report_dict.contains_key("epidPseudonym") {
        error!("AVR does not contain an EPID psuedonym");
        return Err(());
    }
    // 7. Includes a nonce
    if !verification_report_dict.contains_key("nonce") {
        error!("AVR does not contain a nonce");
        return Err(());
    }
    // AVR verification done
    Ok(())
}
