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

extern crate hyper_proxy;
extern crate hyper_tls;
extern crate native_tls;

use self::hyper_proxy::{Intercept, Proxy, ProxyConnector};
use self::hyper_tls::HttpsConnector;
use self::native_tls::{Identity, TlsConnector};
use futures::{future, future::Future, stream::Stream};
use hyper::{
    client::{HttpConnector, ResponseFuture},
    header::HeaderMap,
    Body, Client, Error, StatusCode, Uri,
};
use std::{env, error, fmt};
use tokio::runtime::current_thread::Runtime;

/// Custom error for client utils
#[derive(Debug, Clone)]
pub struct ClientError;

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid value found")
    }
}

impl error::Error for ClientError {
    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

/// read_response_future() would return the ClientResponse which has ```hyper::Body``` and
/// ```hyper::header::HeaderMap```
///
/// Methods to read Body does consume, ideally we should access members through getters
#[derive(Debug)]
pub struct ClientResponse {
    pub body: Body,
    pub header_map: HeaderMap,
}

/// Function to get a http and https compatible client to connect to remote URI.
///
/// Accepts certificate to be trusted as byte array. Returns a ```hyper::Client``` object that
/// can be used to connect to a URI having prefix either http or https.
pub fn get_client(
    der_cert: &[u8],
    password: &str,
) -> Result<Client<ProxyConnector<HttpsConnector<HttpConnector>>, Body>, ClientError> {
    let identity =
        Identity::from_pkcs12(der_cert, password).expect("Error reading identity from cert");
    // client cert information
    let tls_connector = match TlsConnector::builder().identity(identity).build() {
        Ok(tls_connector_built) => tls_connector_built,
        Err(error) => {
            error!("Unable to build TLS connector; More info: {}", error);
            return Err(ClientError);
        }
    };

    let mut http = HttpConnector::new(1);
    // do not enforce http only URI, we are using TlsConnector to build HttpsConnector for https URI
    http.enforce_http(false);
    let https = HttpsConnector::from((http, tls_connector.clone()));
    let mut proxy_connector =
        ProxyConnector::new(https.clone()).expect("Error constructing client");
    // Read proxy environment variable
    let http_proxy = env::var("http_proxy");
    if http_proxy.is_ok() {
        let read_proxy = http_proxy
            .unwrap()
            .parse::<Uri>()
            .expect("Error reading proxy environment");
        let proxy = Proxy::new(Intercept::All, read_proxy);
        // build a client to allow both http and https URI formats
        proxy_connector = match ProxyConnector::from_proxy(https, proxy) {
            Ok(success) => success,
            Err(error) => panic!("{}", error),
        };
        debug!("Using proxy");
    }
    proxy_connector.set_tls(Option::from(tls_connector));
    Ok(Client::builder().build::<_, Body>(proxy_connector))
}

/// Function to read ```hyper::client::ResponseFuture``` (return values of .request(), .get(), .post()
/// etc functions from hyper library).
///
/// Returns result ClientResponse and ClientError.
/// This is a blocking call. A ```tokio_core``` runner instance is created to block until
/// ```ResponseFuture``` is complete.
pub fn read_response_future(response_fut: ResponseFuture) -> Result<ClientResponse, ClientError> {
    let future_response = response_fut
        // 'then' waits for future_response to be ready and calls the closure supplied here on
        // Result of evaluated future. Response object is ready when closure is called.
        .then(move |response_obj| {
            match response_obj {
                Ok(response) => {
                    debug!("Received response result code: {}", response.status());
                    if response.status() >= StatusCode::BAD_REQUEST {
                        error!("Response status is not successful: {}", response.status());
                        return Err(ClientError);
                    }
                    // Borrow response headers, to be passed in ClientResponse
                    let header_map = response.headers().to_owned();
                    let body = response.into_body();
                    let client_response = ClientResponse { body, header_map };
                    Ok(client_response)
                }
                Err(error) => {
                    error!(
                        "Error occurred while waiting for the ResponseFuture {}",
                        error
                    );
                    Err(ClientError)
                }
            }
        });

    // Create a runner instance for evaluating ResponseFuture
    let mut runner = Runtime::new().expect("Error creating runtime");
    // blocks until future is evaluated, otherwise error out
    match runner.block_on(future_response) {
        Ok(successful) => Ok(successful),
        Err(_) => Err(ClientError),
    }
}

/// Function to read ```hyper::Body``` (body) as string.
///
/// Returns result of ```String``` and ```ClientError```.
/// This is a blocking call. Body is streamed and collected as vector, which later is converted to
/// string representation.
pub fn read_body_as_string(body: Body) -> Result<String, ClientError> {
    body.fold(Vec::new(), |mut vector, chunk| {
        vector.extend_from_slice(&chunk[..]);
        future::ok::<_, Error>(vector)
    })
    // 'then' evaluates Future to Result. Note that body should be available already.
    // Construct a Result of string to be returned when body is available.
    .then(move |body_as_byte_vector| match body_as_byte_vector {
        Ok(byte_vector) => {
            let body =
                String::from_utf8(byte_vector).expect("Error reading body byte stream as string");
            Ok(body)
        }
        Err(error) => {
            error!("Error reading body as string {}", error);
            Err(ClientError)
        }
    })
    // Wait for completion of task assigned to then
    .wait()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{
        header::{HeaderName, HeaderValue},
        service::service_fn_ok,
        Response, Server, Uri,
    };
    use std::fs::File;
    use std::io::Read;
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        str::FromStr,
        sync::atomic::{AtomicBool, Ordering::SeqCst, ATOMIC_BOOL_INIT},
        thread,
    };
    use tokio::runtime::Runtime;

    // Variable so that server is not trying to bind again
    static IS_INITIALIZED: AtomicBool = ATOMIC_BOOL_INIT;
    lazy_static! {
        // Prefixed string values for asserting
        static ref RANDOM_STRING: String = "This string is expected in body".to_string();
        static ref VALID_HEADER_KEY: String = "ValidHeader".to_string();
        static ref VALID_HEADER_VALUE: String = "ValidHeaderValue".to_string();
        static ref INVALID_HEADER_KEY: String = "InvalidHeader".to_string();
        static ref INVALID_HEADER_VALUE: String = "InvalidHeaderValue".to_string();
    }

    #[test]
    fn test_read_body_as_string() {
        let body_composed = Body::from(RANDOM_STRING.clone());
        let what_is_read_from_body =
            read_body_as_string(body_composed).expect("Error reading body as string");
        assert_eq!(what_is_read_from_body, RANDOM_STRING.clone());
    }

    #[test]
    fn test_read_response_body_as_string() {
        if IS_INITIALIZED.load(SeqCst) == false {
            mock_setup_server();
        }
        let client = Client::new();
        let address = "http://127.0.0.1:".to_string().to_owned() + "8080";
        let future_response = client.get(
            address
                .parse::<Uri>()
                .expect("Error converting string to Uri"),
        );
        let what_is_read_from_response =
            read_response_future(future_response).expect("Error reading response");
        let body = what_is_read_from_response.body;
        let what_is_read_from_body =
            read_body_as_string(body).expect("Error reading body as string");
        assert_eq!(what_is_read_from_body, RANDOM_STRING.clone());
    }

    #[test]
    fn test_read_response_body_as_string_with_header() {
        if IS_INITIALIZED.load(SeqCst) == false {
            mock_setup_server();
        }
        let client = Client::new();
        let address = "http://127.0.0.1:".to_string().to_owned() + "8080";
        let future_response = client.get(
            address
                .parse::<Uri>()
                .expect("Error converting string to Uri"),
        );
        let what_is_read_from_response =
            read_response_future(future_response).expect("Error reading response");
        let body = what_is_read_from_response.body;
        let what_is_read_from_body =
            read_body_as_string(body).expect("Error reading body as string");
        assert_eq!(what_is_read_from_body, RANDOM_STRING.clone());
        let header_map_read = what_is_read_from_response.header_map;
        assert!(header_map_read.contains_key(VALID_HEADER_KEY.clone()));
        assert_eq!(
            header_map_read
                .get(VALID_HEADER_KEY.clone())
                .expect("Error reading header value"),
            VALID_HEADER_VALUE.clone().as_str()
        );
    }

    #[test]
    fn test_read_response_body_as_string_with_invalid_header() {
        if IS_INITIALIZED.load(SeqCst) == false {
            mock_setup_server();
        }
        let client = Client::new();
        let address = "http://127.0.0.1:".to_string().to_owned() + "8080";
        let future_response = client.get(
            address
                .parse::<Uri>()
                .expect("Error converting string to Uri"),
        );
        let what_is_read_from_response =
            read_response_future(future_response).expect("Error reading response");
        let body = what_is_read_from_response.body;
        let what_is_read_from_body =
            read_body_as_string(body).expect("Error reading body as string");
        assert_eq!(what_is_read_from_body, RANDOM_STRING.clone());
        let header_map_read = what_is_read_from_response.header_map;
        assert_eq!(
            header_map_read.contains_key(INVALID_HEADER_KEY.clone()),
            false
        );
    }

    #[test]
    #[ignore]
    fn test_get_client() {
        if IS_INITIALIZED.load(SeqCst) == false {
            mock_setup_server();
        }
        let cert = read_binary_file("src/tests/resources/dummy_cert.pfx");
        let client = get_client(cert.as_ref(), "").expect("Error creating the client instance");
        let address = "http://127.0.0.1:".to_string().to_owned() + "8080";
        let future_response = client.get(
            address
                .parse::<Uri>()
                .expect("Error converting string to Uri"),
        );
        let what_is_read_from_response =
            read_response_future(future_response).expect("Error reading body as string");
        let body = what_is_read_from_response.body;
        let what_is_read_from_body =
            read_body_as_string(body).expect("Error reading body as string");
        assert_eq!(what_is_read_from_body, RANDOM_STRING.clone());
    }

    #[test]
    fn test_connect_to_google() {
        let cert = read_binary_file("src/tests/resources/dummy_cert.pfx");
        let client = get_client(cert.as_ref(), "").expect("Error creating the client instance");
        let address = "https://www.google.com".to_string();
        let future_response = client.get(
            address
                .parse::<Uri>()
                .expect("Error converting string to Uri"),
        );
        let what_is_read_from_response =
            read_response_future(future_response).expect("Error reading body as string");
        let body = what_is_read_from_response.body;
        let what_is_read_from_body =
            read_body_as_string(body).expect("Error reading body as string");
        assert_ne!(what_is_read_from_body.len(), 0)
    }

    #[test]
    fn test_not_ok_read_response_body_with_string() {
        mock_setup_bad_server();
        let client = Client::new();
        let address = "http://127.0.0.1:".to_string().to_owned() + "8081";
        let future_response = client.get(
            address
                .parse::<Uri>()
                .expect("Error converting string to Uri"),
        );
        match read_response_future(future_response) {
            Ok(_response_body) => assert!(false),
            Err(_error) => assert!(true),
        };
    }

    fn mock_setup_server() {
        IS_INITIALIZED.store(true, SeqCst);
        let loopback_addr = Ipv4Addr::new(127, 0, 0, 1);
        // TODO: Use random port here
        let socket_addr: SocketAddr = SocketAddr::from(SocketAddrV4::new(loopback_addr, 8080));
        let new_service = move || {
            service_fn_ok(|_| {
                let mut response = Response::new(Body::from(RANDOM_STRING.clone()));
                response.headers_mut().insert(
                    HeaderName::from_str(VALID_HEADER_KEY.as_str())
                        .expect("Error converting string to header name"),
                    HeaderValue::from_str(VALID_HEADER_VALUE.as_str())
                        .expect("Error converting string to header value"),
                );
                response
            })
        };
        let server = Server::bind(&socket_addr)
            .serve(new_service)
            .map_err(|e| panic!("server error: {}", e));

        // TODO: Force this thread to close after test case ends
        thread::spawn(|| {
            let mut handler = Runtime::new().expect("Error creating runner instance");
            handler
                .block_on(server)
                .expect("Error blocking on the service")
        });
    }

    fn mock_setup_bad_server() {
        let loopback_addr = Ipv4Addr::new(127, 0, 0, 1);
        // TODO: Use random port here
        let socket_addr: SocketAddr = SocketAddr::from(SocketAddrV4::new(loopback_addr, 8081));
        let new_service = move || {
            service_fn_ok(|_| {
                let mut response = Response::new(Body::from(RANDOM_STRING.clone()));
                // Return any status >= 400
                // This is to simulate that server is responding bad
                *response.status_mut() =
                    StatusCode::from_u16(400).expect("Error reading status code from integer");
                response
            })
        };
        let server = Server::bind(&socket_addr)
            .serve(new_service)
            .map_err(|e| panic!("server error: {}", e));

        // TODO: Force this thread to close after test case ends
        thread::spawn(|| {
            let mut handler = Runtime::new().expect("Error creating runner instance");
            handler
                .block_on(server)
                .expect("Error blocking on the service")
        });
    }

    fn read_binary_file(filename: &str) -> Vec<u8> {
        let mut file = File::open(filename).unwrap();
        let mut buffer = vec![];
        file.read_to_end(&mut buffer).expect("Read failed!");
        buffer
    }
}
