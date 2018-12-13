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

/// Structure to read IAS proxy server configuration from toml file
#[derive(Debug, Deserialize)]
pub struct IasProxyConfig {
    proxy_ip: String,
    proxy_port: String,
    ias_url: String,
    spid_cert_file: String,
    password: String,
}

impl IasProxyConfig {
    // Note: new for config is used only for writing test cases, ideally this is structure filled
    // by deserialization step. Unit tests for getting a new IasProxyServer would need object of
    // IasProxyConfig be present.
    /// To create a new IasProxyConfig
    #[cfg(test)]
    pub fn new(
        proxy_ip: String,
        proxy_port: String,
        ias_url: String,
        spid_cert_file: String,
        password: String,
    ) -> Self {
        IasProxyConfig {
            proxy_ip,
            proxy_port,
            ias_url,
            spid_cert_file,
            password,
        }
    }

    /// Getters fot the members
    pub fn get_proxy_ip(&self) -> String {
        self.proxy_ip.clone()
    }

    pub fn get_proxy_port(&self) -> String {
        self.proxy_port.clone()
    }

    pub fn get_ias_url(&self) -> String {
        self.ias_url.clone()
    }

    pub fn get_spid_cert_file(&self) -> String {
        self.spid_cert_file.clone()
    }

    pub fn get_password(&self) -> String {
        self.password.clone()
    }
}
