/*
 Copyright 2018 Intel Corporation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
------------------------------------------------------------------------------
*/

extern crate serde;

use client_utils::{get_client, read_response_future, ClientError, ClientResponse};
use hyper::{header, header::HeaderValue, Body, Method, Request, Uri};
use serde_json;
use std::{collections::HashMap, str, time::Duration};

/// Structure for storing IAS connection information
#[derive(Debug, Clone)]
pub struct IasClient {
    // IAS URL to connect to
    ias_url: String,
    // Root cert to be trusted
    spid_cert: Vec<u8>,
    // Password for PKCS12 format file
    password: String,
    // Timeout for the client requests in seconds
    timeout: Duration,
}

const SIGRL_LINK: &str = "/attestation/sgx/v2/sigrl";
const AVR_LINK: &str = "/attestation/sgx/v2/report";
const EMPTY_STR: &str = "";
// Note: Structure can be used for serialization and deserialization, but it won't skip null values
const ISV_ENCLAVE_QUOTE: &str = "isvEnclaveQuote";
const PSE_MANIFEST: &str = "pseManifest";
const NONCE: &str = "nonce";
// timeout constants
const DEFAULT_TIMEOUT_SECS: u64 = 300;
const DEFAULT_TIMEOUT_NANO_SECS: u32 = 0;

/// Implement how the IasClient is going to be used
impl IasClient {
    /// default constructor for IasClient, remember to use setters later
    pub fn default() -> Self {
        IasClient {
            ias_url: String::new(),
            spid_cert: vec![],
            password: EMPTY_STR.to_string(),
            timeout: Duration::new(DEFAULT_TIMEOUT_SECS, DEFAULT_TIMEOUT_NANO_SECS),
        }
    }

    /// constructor for IasClient
    pub fn new(url: String, cert: Vec<u8>, passwd: String, time: Option<u64>) -> Self {
        IasClient {
            ias_url: url,
            spid_cert: cert,
            password: passwd,
            timeout: Duration::new(
                time.unwrap_or(DEFAULT_TIMEOUT_SECS),
                DEFAULT_TIMEOUT_NANO_SECS,
            ),
        }
    }

    /// Setters for IasClient structure
    pub fn set_ias_url(&mut self, url: String) {
        self.ias_url = url;
    }

    pub fn set_spid_cert(&mut self, cert: Vec<u8>) {
        self.spid_cert = cert;
    }

    pub fn set_password(&mut self, passwd: String) {
        self.password = passwd;
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Get request to receive signature revocation list for input Group ID (gid). Accepts
    /// optional 'gid' and optional 'api_path' as input. Optional 'gid' field is used for the
    /// case of IAS Proxy server, which receives request with 'gid' appended already.
    ///
    /// return: A ClientResponse object containing the following:
    ///     Body of the response has 'signature revocation list', the body of the response from IAS.
    ///     Header of the response has nothing.
    pub fn get_signature_revocation_list(
        &self,
        gid: Option<&str>,
        api_path: Option<&str>,
    ) -> Result<ClientResponse, ClientError> {
        // Path to get SigRL from
        let mut final_path = String::new();
        final_path.push_str(self.ias_url.as_str());
        // Received REST path if any
        let received_path = match api_path {
            Some(path_present) => path_present,
            _ => SIGRL_LINK,
        };
        final_path.push_str(received_path);
        // Append gid to the path if present
        let received_gid = match gid {
            Some(gid_present) => {
                final_path.push_str("/");
                gid_present
            }
            _ => "",
        };
        final_path.push_str(received_gid);
        let url = final_path
            .parse::<Uri>()
            .expect("Error constructing URI from string");
        debug!("Fetching SigRL from: {}", url);

        // Send request to get SigRL
        let client = get_client(&self.spid_cert, self.password.as_str())
            .expect("Error creating http/s client");
        // TODO: Add logic for request timeout
        let response_fut = client.get(url);
        read_response_future(response_fut)
    }

    /// Post request to send Attestation Enclave Payload and get response having Attestation
    /// Verification Report. Accepts quote and optional values pse_manifest, nonce as input.
    ///
    /// return: A ClientResponse object containing the following:
    ///     Body of the response has 'attestation verification report', the body (JSON) of the
    ///         response from ISA.
    ///     Header of the response has 'signature', the base 64-encoded RSA-SHA256 signature of the
    ///         response body (aka, AVR) using the report key.
    pub fn post_verify_attestation(
        &self,
        quote: &[u8],
        manifest: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<ClientResponse, ClientError> {
        // REST API to connect to for getting AVR
        let mut final_path = String::new();
        final_path.push_str(self.ias_url.as_str());
        final_path.push_str("/");
        final_path.push_str(AVR_LINK);
        let url = final_path
            .parse::<Uri>()
            .expect("Error constructing URI from string");
        debug!("Posting attestation verification request to: {}", url);

        // Construct AEP, request parameter
        // Note: Replace following HashMap with a structure if Integration test with IAS succeeds
        // with keys in request json with empty value. With following code, we are avoiding even
        // addition of keys in request json.
        let mut request_aep: HashMap<String, String> = HashMap::new();
        request_aep.insert(
            String::from(ISV_ENCLAVE_QUOTE),
            str::from_utf8(quote)
                .expect("Error occurred when converting quote to string")
                .to_owned(),
        );
        // Optional manifest, add to request param if present
        if manifest.is_some() {
            request_aep.insert(String::from(PSE_MANIFEST), manifest.unwrap().to_owned());
        }
        // Optional nonce, add to request param if present
        if nonce.is_some() {
            request_aep.insert(String::from(NONCE), nonce.unwrap().to_string());
        }
        // Construct hyper's request to be sent
        let mut req = Request::new(Body::from(
            serde_json::to_string(&request_aep).expect("Error occurred during AEP serialization"),
        ));
        *req.method_mut() = Method::POST;
        *req.uri_mut() = url.clone();
        req.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        debug!("Posting attestation evidence payload: {:#?}", request_aep);

        // Send request to get AVR
        let client = get_client(&self.spid_cert, self.password.as_str())
            .expect("Error creating http client");
        let response_fut = client.request(req);
        // TODO: Add logic for request timeout
        read_response_future(response_fut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_DURATION: u64 = 300;
    const DUMMY_DURATION: u64 = 0;
    const DEFAULT_URL: &str = "";
    const DUMMY_URL: &str = "dummy.url";
    const DUMMY_PASSWORD: &str = "dummy password";
    lazy_static! {
        static ref DEFAULT_CERT: Vec<u8> = [].to_vec();
        static ref DUMMY_CERT: Vec<u8> = vec![1, 2, 3, 4];
    }

    #[test]
    fn test_default_ias_client_creation() {
        let default_client = IasClient::default();
        assert_eq!(default_client.ias_url, DEFAULT_URL.clone());
        assert_eq!(default_client.spid_cert.len(), DEFAULT_CERT.len());
        assert_eq!(default_client.timeout.as_secs(), DEFAULT_DURATION);
    }

    #[test]
    fn test_new_ias_client_creation() {
        let new_ias_client = IasClient::new(
            DUMMY_URL.clone().to_string(),
            DUMMY_CERT.to_vec(),
            DUMMY_PASSWORD.to_string(),
            Option::from(DUMMY_DURATION),
        );
        assert_eq!(new_ias_client.ias_url, DUMMY_URL.clone());
        assert_eq!(new_ias_client.spid_cert.len(), DUMMY_CERT.len());
        assert_eq!(new_ias_client.timeout.as_secs(), DUMMY_DURATION);
    }

    #[test]
    fn test_new_ias_client_with_assignment() {
        let mut default_client = IasClient::default();
        default_client.set_ias_url(DUMMY_URL.clone().to_string());
        default_client.set_spid_cert(DUMMY_CERT.to_vec());
        default_client.set_timeout(Duration::new(DUMMY_DURATION, 0));
        assert_eq!(default_client.ias_url, DUMMY_URL.clone());
        assert_eq!(default_client.spid_cert.len(), DUMMY_CERT.len());
        assert_eq!(default_client.timeout.as_secs(), DUMMY_DURATION);
    }
    // Reading from response / body, reading of headers are handled in client_utils.rs
    // Please find the file for unit tests on those
}
