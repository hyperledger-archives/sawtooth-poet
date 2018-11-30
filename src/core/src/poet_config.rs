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

/// Structure to read IAS proxy server configuration from toml file
#[derive(Debug, Deserialize, Clone)]
pub struct PoetConfig {
    spid: String,
    ias_url: String,
    spid_cert_file: String,
    password: String,
    rest_api: String,
    ias_report_key_file: String,
    poet_client_private_key_file: String,
}

impl PoetConfig {
    /// Getters fot the members
    pub fn get_spid(&self) -> String {
        return self.spid.clone();
    }

    pub fn get_ias_url(&self) -> String {
        return self.ias_url.clone();
    }

    pub fn get_spid_cert_file(&self) -> String {
        return self.spid_cert_file.clone();
    }

    pub fn get_password(&self) -> String {
        return self.password.clone();
    }

    pub fn get_rest_api(&self) -> String {
        return self.rest_api.clone();
    }

    pub fn get_ias_report_key_file(&self) -> String {
        return self.ias_report_key_file.clone();
    }

    pub fn get_poet_client_private_key_file(&self) -> String {
        return self.poet_client_private_key_file.clone();
    }
}
