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

extern crate futures;
extern crate hyper;
extern crate ias_client;
extern crate serde;
extern crate serde_json;

use ias_proxy_config::IasProxyConfig;
use lru_cache::LruCache;
use self::futures::{Future,
                    future};
use self::hyper::{Body,
                  Error,
                  header::{HeaderMap,
                           HeaderValue},
                  Method,
                  Request,
                  Response,
                  Server,
                  service::service_fn,
                  StatusCode};
use self::ias_client::{client_utils,
                       client_utils::{ClientError,
                                      ClientResponse},
                       ias_client::IasClient};
use std::{borrow::Borrow,
          net::SocketAddr,
          str::FromStr,
          sync::Mutex};
use utils::read_binary_file;

/// type definition for response sent from web server
type ResponseBox = Box<Future<Item=Response<Body>, Error=Error> + Send>;

/// structure defining IAS proxy server
pub struct IasProxyServer {
    ias_proxy_ip: String,
    ias_proxy_port: String,
    ias_client: Box<IasClient>,
}

/// Request body from client, proxy server may deserialize the reuqest in order to get quote if
/// request is for attestation verification report.
#[derive(Deserialize)]
struct IasAVRRequestBody {
    #[serde(rename = "isvEnclaveQuote")]
    isv_enclave_quote: String,
    #[serde(rename = "pseManifest")]
    pse_manifest: String,
    nonce: u64,
}

/// ClientResponse decoded information stored in cache
#[derive(Debug, Clone)]
struct IasResponse {
    body_string: String,
    header_map: HeaderMap,
}

lazy_static! {
    static ref sig_rl_cache: Mutex<LruCache<String, IasResponse>> =
        Mutex::new(LruCache::new(None));
    static ref attestation_cache: Mutex<LruCache<String, IasResponse>> =
        Mutex::new(LruCache::new(None));
}

const SIG_RL_LINK: &str = "/attestation/sgx/v2/sigrl";
const AVR_LINK: &str = "/attestation/sgx/v2/report";
const IP_PORT_DELIMITER: &str = ":";
const UNKNOWN_ERROR_STATUS_CODE: u16 = 520;

impl IasProxyServer {
    /// Create new instance of IasProxyServer
    fn new(
        config: IasProxyConfig
    ) -> Self {
        IasProxyServer {
            ias_proxy_ip: config.get_proxy_ip(),
            ias_proxy_port: config.get_proxy_port(),
            // Construct new IasClient with input config parameters
            ias_client: Box::new(
                IasClient::new(
                    config.get_ias_url(),
                    read_binary_file(config.get_spid_cert_file().as_str()),
                    config.get_password(),
                    None,
                )
            ),
        }
    }

    /// run method to start listening on the identified IP and port
    pub fn run(
        &self
    ) {
        // Start the web server on the configured URL
        let mut path = String::new();
        path.push_str(self.ias_proxy_ip.as_str());
        path.push_str(IP_PORT_DELIMITER);
        path.push_str(self.ias_proxy_port.as_str());
        info!("Proxy server will be started as {}", path);

        // Construct socket address, panics if binding fails
        let socket_addr: SocketAddr = match SocketAddr::from_str(&path) {
            Ok(address_bind_successful) => address_bind_successful,
            Err(err) => panic!("Error binding the address: {}", err),
        };
        info!("Socket binding successful");

        // ias_client's lifetime must be static for not to clone
        let ias_client = self.ias_client.clone();
        // TODO: Store this server instance and call shutdown
        let new_service = move || {
            let ias_client = ias_client.clone();
            // service_fn() creates a hyper's Service. It accepts a closure for handling the
            // request, future response is constructed when request is served.
            service_fn(move |req|
                respond_to_request(req, ias_client.borrow())
            )
        };

        // Run proxy server in current thread, serve or panic
        hyper::rt::run(
            Server::bind(&socket_addr)
                .serve(new_service)
                .map_err(|e| {
                    panic!("Server error: {}", e);
                })
        )
    }

    /// Stop listening on the port
    #[allow(dead_code)]
    pub fn stop(
        &self
    ) {
        // TODO: Need to stop the server started and clear the cache
        unimplemented!()
    }
}

/// Function to construct response by parsing request from IasClient. Accepts the request
/// parameter and reference to IasClient object. First checks if cached content has the response
/// corresponding to the request, if not present go and request IAS, get response, store in
/// cache, construct response back.
///
/// return: A ```Box<Future<Item=Response<Body>, Error=hyper::Error> + Send>``` object:
///     Response message to be sent back for the request.
fn respond_to_request(
    req: Request<Body>,
    ias_client_obj: &IasClient,
) -> ResponseBox {

    // Get response parsing request parameters
    match *req.method() {
        Method::GET => {
            return handle_get_request(
                req,
                ias_client_obj,
            );
        }

        Method::POST => {
            return handle_post_request(
                req,
                ias_client_obj,
            );
        }

        // Proxy server doesn't support any other request types other than GET and POST.
        _ => {
            return send_response(
                StatusCode::NOT_FOUND,
                None,
                None,
            );
        }
    };
}

/// Handle get request from the proxy, this should only be valid for getting signature revocation
/// list. Proxy server doesn't support other GET requests. See ```response_to_request()``` for
/// detailed description.
fn handle_get_request(
    req: Request<Body>,
    ias_client_obj: &IasClient,
) -> ResponseBox {

    // Get path from request
    let path = req.uri().path().to_owned();

    if path.contains(SIG_RL_LINK) == false {
        return send_response(
            StatusCode::NOT_FOUND,
            None,
            None,
        );
    }
    // Search cache for the signature revocation list
    let mut sig_rl_cache_lock = sig_rl_cache
        .lock()
        .expect("Error acquiring SigRL cache lock");
    let cached = sig_rl_cache_lock.get(&path);
    // If there's cache, send it as response, otherwise request from IAS
    let response_to_send = match cached {
        Some(cached_revocation_list) => {
            Ok(cached_revocation_list.clone())
        }
        None => {
            // Request has gid in URI path, we do not need to send gid explicit
            let result =
                ias_client_obj.get_signature_revocation_list(None, Some(path.as_str()));
            let ias_response_result =
                ias_response_from_client_response(result);
            if ias_response_result.is_ok() {
                let ias_response = ias_response_result.clone().unwrap();
                sig_rl_cache
                    .lock()
                    .expect("Error acquiring SigRL cache lock")
                    .set(path, ias_response);
            }
            ias_response_result
        }
    };
    match response_to_send {
        Ok(ias_response) => {
            // Send the response to requester
            let mut headers = ias_response.header_map;
            let body = Body::from(ias_response.body_string);
            return send_response(
                StatusCode::OK,
                Option::from(headers),
                Option::from(body),
            );
        }
        Err(error) => {
            error!("Error occurred {}", error);
            // Unknown error, ideally this case should not occur. Cache must be corrupted or
            // IAS returned error.
            return send_response(
                StatusCode::from_u16(UNKNOWN_ERROR_STATUS_CODE)
                    .expect("Error converting status code"),
                None,
                None,
            );
        }
    };
}

/// Handle post request from the proxy, this should only be valid for getting attestation
/// verification report. Proxy server doesn't support other POST requests. See
/// ```response_to_request()``` for detailed description.
fn handle_post_request(
    req: Request<Body>,
    ias_client_obj: &IasClient,
) -> ResponseBox {

    // Get path from request
    let path = req.uri().path().to_owned();

    if path.contains(AVR_LINK) == false {
        return send_response(
            StatusCode::NOT_FOUND,
            None,
            None,
        );
    }
    // read json input data
    let read_body_result = client_utils::read_body_as_string(req.into_body());
    if read_body_result.is_err() {
        return send_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            None,
        );
    }
    let read_body = read_body_result.unwrap();
    let json_body: IasAVRRequestBody = serde_json::from_str(read_body.as_str())
        .expect("Error deserializing IAS verification report");
    let quote = json_body.isv_enclave_quote;
    if quote.is_empty() {
        return send_response(
            StatusCode::NOT_FOUND,
            None,
            None,
        );
    }
    // If no input quote in attestation cache (isvEnclaveQuote) then return 404
    // otherwise check the cache or send the request to actual IAS server
    let mut attestation_cache_lock = attestation_cache
        .lock()
        .expect("Error acquiring AVR cache lock");
    let cached_avr = attestation_cache_lock.get(&quote);
    let avr = match cached_avr {
        // Cache is present, it can be sent
        Some(cache_present) => {
            Ok(cache_present.clone())
        }
        // Cache is not presnet, request from IAS and add to cache
        None => {
            let result =
                ias_client_obj.post_verify_attestation(
                    quote.as_bytes(),
                    Option::from(json_body.pse_manifest.as_str()),
                    Option::from(json_body.nonce),
                );
            let ias_response_result = ias_response_from_client_response(result);
            if ias_response_result.is_ok() {
                let ias_response = ias_response_result.clone().unwrap();
                // Store the response to the cache
                attestation_cache
                    .lock()
                    .expect("Error acquiring AVR cache lock")
                    .set(quote, ias_response);
            }
            ias_response_result
        }
    };
    match avr {
        Ok(avr_content) => {
            // AVR is read, send it to the requester
            let body = Body::from(avr_content.body_string);
            let mut headers = avr_content.header_map;
            return send_response(
                StatusCode::OK,
                Option::from(headers),
                Option::from(body),
            );
        }
        Err(error) => {
            error!("Error occurred {}", error);
            // Unknown error, ideally this case should not occur. Cache must be corrupted or
            // IAS returned error.
            return send_response(
                StatusCode::from_u16(UNKNOWN_ERROR_STATUS_CODE)
                    .expect("Error converting status code"),
                None,
                None,
            );
        }
    }
}

/// Function to construct ```hyper::Response``` for the supplied input parameters.
/// Accepts http status code and Optional headers, body to be packed in response object.
///
/// return: A ```Box<Future<Item=Response<Body>, Error=hyper::Error> + Send>``` object:
///     Response message to be sent back for the request.
fn send_response(
    status_code: StatusCode,
    headers: Option<HeaderMap<HeaderValue>>,
    body: Option<Body>,
) -> ResponseBox {

    // Construct response with empty body, then fill input parameters
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status_code;
    if body.is_some() {
        *response.body_mut() = body.unwrap();
    };
    if headers.is_some() {
        *response.headers_mut() = headers.unwrap();
    }
    Box::new(future::ok(response))
}

/// Function to converts Result<&ClientResponse, ClientError> to Result<IasResponse, ClientError>
/// this is done so to store ClientResponse in LRU cache. ClientResponse cannot be directly
/// stored in cache because it has ```hyper::Body``` which is stream and cannot be cloned.
///
/// return: Result<IasResponse, ClientError>
fn ias_response_from_client_response(
    client_response: Result<ClientResponse, ClientError>
) -> Result<IasResponse, ClientError> {

    // Start conversion, need to parse client_resposne
    match client_response {
        Ok(successful_response) => {
            // If there's successful response, then read body to string
            let body_string_result = client_utils::read_body_as_string(successful_response.body);

            // If reading body as string is successful then construct IasResponse
            return match body_string_result {
                Ok(body_read_successfully) => {
                    Ok(IasResponse {
                        body_string: body_read_successfully,
                        header_map: successful_response.header_map,
                    })
                }

                // Conversion of body to string failed
                Err(body_read_failed) => {
                    Err(body_read_failed)
                }
            };
        }

        // ClientError occurred, there's no valid response to convert
        Err(error_response) => {
            return Err(error_response);
        }
    }
}

/// Function to construct ```IasProxyServer``` object with the input proxy configuration file.
/// 'new()' for ```IasProxyServer``` is private, so use this public method to get instance of it.
///
/// return: A ```IasProxyServer``` object
pub fn get_proxy_server(
    proxy_config: IasProxyConfig
) -> IasProxyServer {

    // Read toml config file as input.
    // Conversion to struct would have failed if fields in file doesn't match expectation
    // So the config map here has all required values set in it.
    let ias_server = IasProxyServer::new(proxy_config);
    ias_server
}

#[cfg(test)]
mod tests {
    use self::hyper::header::HeaderName;
    use super::*;

    #[test]
    fn test_get_proxy_server() {
        let ias_proxy_config = IasProxyConfig::new(
            "127.0.0.1".to_string(),
            "8000".to_string(),
            "https://dummy-ias-url".to_string(),
            "src/tests/dummy_cert.pfx".to_string(),
            "".to_string(),
        );
        // This would also test new function of IasProxyServer
        let ias_server = get_proxy_server(ias_proxy_config);
        assert_eq!(ias_server.ias_proxy_ip, "127.0.0.1");
        assert_eq!(ias_server.ias_proxy_port, "8000");
    }

    #[test]
    fn test_ias_response_from_client_response() {
        let mut header_map = HeaderMap::new();
        header_map.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("plain/text"),
        );
        let client_response = Ok(ClientResponse {
            body: Body::from("dummy text"),
            header_map,
        });
        let ias_response = ias_response_from_client_response(client_response);
        match ias_response {
            Ok(expected) => assert_eq!(expected.body_string, "dummy text"),
            Err(_unexpected) => assert!(false),
        };
    }

    #[test]
    fn test_erraneous_ias_response_from_client_response() {
        let client_response = Err(ClientError);
        let ias_response = ias_response_from_client_response(client_response);
        match ias_response {
            Ok(_unexpected) => assert!(false),
            Err(_expected) => assert!(true),
        };
    }
}
