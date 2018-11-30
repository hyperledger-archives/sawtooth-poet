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

use std::collections::HashMap;
use sawtooth_sdk::consensus::engine::BlockId;
use service::Poet2Service;

#[derive(Clone, Debug, Default)]
pub struct Poet2SettingsView {
    settings : HashMap<String, String>,
}

impl Poet2SettingsView {
    pub fn new() -> Poet2SettingsView {
        Poet2SettingsView {
            settings : HashMap::new(),
        }
    }

    pub fn init(&mut self, block_id: BlockId, service: &mut Poet2Service) {
        let settings_keys = vec![
            "sawtooth.consensus.poet2.block_claim_delay",
            "sawtooth.consensus.poet2.initial_wait_time",
            "sawtooth.consensus.poet2.key_block_claim_limit",
            "sawtooth.consensus.poet2.population_estimate_sample_size",
            "sawtooth.consensus.poet2.registration_retry_delay",
            "sawtooth.consensus.poet2.signup_commit_maximum_delay",
            "sawtooth.consensus.poet2.target_wait_time",
            "sawtooth.consensus.poet2.z_test_maximum_win_deviation",
            "sawtooth.consensus.poet2.z_test_minimum_win_count",
        ];

        self.settings = service
                 .get_settings(block_id, settings_keys
                                             .into_iter()
                                             .map(String::from).collect())
                 .expect("Failed to get settings keys");
    }

    pub fn _get_config_value_as_u64(&self, config_key : &str,
                                in_default_value : u64)
                                -> u64 {
        if let Some(raw_value) = self.settings.get(config_key) {
            let parsed: Result<u64, _> = raw_value.parse();
            if let Ok(config_value) = parsed {
                  return config_value;
            }
        }
        in_default_value
    }

    pub fn _get_config_value_as_f64(&self, config_key : &str,
                                in_default_value : f64)
                                -> f64 {
        if let Some(raw_value) = self.settings.get(config_key) {
            let parsed: Result<f64, _> = raw_value.parse();
            if let Ok(config_value) = parsed {
                  return config_value;
            }
        }
        in_default_value
    }

    pub fn block_claim_delay(&self) -> u64 {
        let default_block_claim_delay = 1_u64;
        self._get_config_value_as_u64(
              "sawtooth.consensus.poet2.block_claim_delay",
                                 default_block_claim_delay)
    }

    pub fn initial_wait_time(&self) -> f64 {
        let default_initial_wait_time = 3000.0_f64;
        self._get_config_value_as_f64(
              "sawtooth.consensus.poet2.initial_wait_time",
                                 default_initial_wait_time)
    }

    pub fn key_block_claim_limit(&self) -> u64 {
        let default_key_block_claim_limit = 250_u64;
        self._get_config_value_as_u64(
               "sawtooth.consensus.poet2.key_block_claim_limit",
                                 default_key_block_claim_limit)
    }

    pub fn population_estimate_sample_size(&self) -> u64 {
        let default_population_estimate_sample_size = 50_u64;
        self._get_config_value_as_u64(
               "sawtooth.consensus.poet2.population_estimate_sample_size",
                                 default_population_estimate_sample_size)
    }

    pub fn registration_retry_delay(&self) -> u64 {
        let default_registration_retry_delay = 10_u64;
        self._get_config_value_as_u64(
               "sawtooth.consensus.poet2.registration_retry_delay",
                                 default_registration_retry_delay)
    }

    pub fn signup_commit_maximum_delay(&self) -> u64 {
        let default_signup_commit_maximum_delay = 10_u64;
        self._get_config_value_as_u64(
               "sawtooth.consensus.poet2.signup_commit_maximum_delay",
                                 default_signup_commit_maximum_delay)
    }

    pub fn target_wait_time(&self) -> f64 {
        let default_target_wait_time = 20.0_f64;
        self._get_config_value_as_f64("sawtooth.consensus.poet2.target_wait_time",
                                 default_target_wait_time)
    }

    pub fn z_test_maximum_win_deviation(&self) -> f64 {
        let default_z_test_maximum_win_deviation = 3.075_f64;
        self._get_config_value_as_f64(
               "sawtooth.consensus.poet2.z_test_maximum_win_deviation",
                                 default_z_test_maximum_win_deviation)
    }

    pub fn z_test_minimum_win_count(&self) -> u64 {
        let default_z_test_minimum_win_count = 3_u64;
        self._get_config_value_as_u64(
               "sawtooth.consensus.poet2.z_test_minimum_win_count",
                                 default_z_test_minimum_win_count)
    }
}
