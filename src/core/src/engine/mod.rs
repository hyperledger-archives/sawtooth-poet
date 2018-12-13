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

extern crate sawtooth_sdk;

use database::CliError;
use database::config;
use database::lmdb;
use enclave_sgx::EnclaveConfig;
use poet2_util;
use poet2_util::read_file_as_string_ignore_line_end;
use poet_config::PoetConfig;
use registration::do_create_registration;
use registration::save_batchlist_to_file;
use registration::submit_batchlist_to_rest_api;
use sawtooth_sdk::consensus::{engine::*, service::Service};
use sawtooth_sdk::messages::batch::BatchList;
use self::check_consensus as czk;
use self::consensus_state_store::ConsensusStateStore;
use service::Poet2Service;
use settings_view::Poet2SettingsView;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;
use std::time::Instant;

pub mod check_consensus;
pub mod consensus_state_store;
pub mod consensus_state;
pub mod fork_resolver;

const MAXIMUM_NONCE_LENGTH: usize = 32;
const BATCHES_REST_API: &str = "batches";

pub struct Poet2Engine {
    enclave: EnclaveConfig,
    config: PoetConfig,
    validator_id: String,
    batch_list: BatchList,
}

impl Poet2Engine {
    pub fn new(config: &PoetConfig) -> Self {
        Self::create_poet_engine(config)
    }

    fn create_poet_engine(config: &PoetConfig) -> Self {
        // Read validator ID, validator's public key is used as identifier
        let validator_id = read_file_as_string_ignore_line_end(config.get_validator_pub_key().as_str());

        // Initialize enclave
        let mut enclave = Self::initialize_enclave(config);

        // Create signup information
        let signup_info = enclave.create_signup_info(
            validator_id.as_str(),
            config,
        );

        // Generate nonce, PoET public key is unique every time enclave is initialized. Take hash
        // of it upto maximum nonce length for nonce.
        let (poet_public_key, _) = enclave.get_signup_parameters();
        let nonce = &poet2_util::sha512_from_str(poet_public_key.as_str())[..MAXIMUM_NONCE_LENGTH];

        // Send signup information to validator registry TP
        // It does send registration request to rest-api if not a genesis node
        // In case of genesis node, creates a batch file in the specified location, defaulting to
        // current working directory from where PoET engine is run.
        let batch_list = do_create_registration(config, nonce, &signup_info);

        // Call the batches REST API with composed payload bytes to be sent
        if config.is_genesis() {
            save_batchlist_to_file(
                config.get_genesis_batch_path().as_str(),
                &batch_list,
            )
        }

        // Create a PoET engine object and return
        Poet2Engine {
            enclave,
            config: config.clone(),
            validator_id,
            batch_list,
        }
    }

    fn initialize_enclave(config: &PoetConfig) -> EnclaveConfig {
        let mut enclave = EnclaveConfig::default();
        enclave.initialize_enclave(config);
        enclave.initialize_remote_attestation(config);
        enclave
    }
}

impl Engine for Poet2Engine {
    fn start(
        &mut self,
        updates: Receiver<Update>,
        service: Box<Service>,
        startup_state: StartupState,
    ) -> Result<(), Error> {
        info!("Started PoET 2 Engine...");

        // Register if it's not genesis node
        if !self.config.is_genesis() {
            submit_batchlist_to_rest_api(
                self.config.get_rest_api().as_str(),
                BATCHES_REST_API,
                self.batch_list.clone(),
            );
        }

        let validator_id = self.validator_id.clone();

        let chain_head = startup_state.chain_head;

        // TODO: Refactor service code and avoid cloning enclave object.
        let mut service = Poet2Service::new(service, self.enclave.clone());

        let lmdb_ctx = create_lmdb_context()
            .expect("Failed to create context");
        let mut state_store = open_statestore(&lmdb_ctx)
            .expect("Failed to create state store");

        let mut is_published_at_height = false;

        // The time keeper variable which martks the start of timer
        let mut start = Instant::now();

        let (poet_pub_key, enclave_quote) = service.enclave.get_signup_parameters();

        debug!("Signup info parameters: poet_pub_key = {}, enclave_quote = {}",
               poet_pub_key, enclave_quote);

        let mut wait_time = Duration::from_secs(service.get_wait_time(
            &chain_head, validator_id.as_str(), &poet_pub_key));
        let mut claim_wait_time = 0;

        let mut poet2_settings_view = Poet2SettingsView::new();
        poet2_settings_view.init(chain_head.block_id.clone(), &mut service);

        service.initialize_block(Some(chain_head.block_id));

        // 1. Wait for an incoming message.
        // 2. Check for exit.
        // 3. Handle the message.
        // 4. Check for publishing.
        loop {
            let incoming_message = updates.recv_timeout(Duration::from_millis(10));
            match incoming_message {
                Ok(update) => {
                    debug!("Received message: {:?}", update);

                    match update {
                        // When a block comes into being internal/external
                        Update::BlockNew(block) => {
                            info!("BlockNew :: Checking consensus data for block_id : {}",
                                  poet2_util::to_hex_string(&block.block_id));

                            if czk::check_consensus(&block, &mut service, validator_id.as_str()) {
                                debug!("Passed consensus check for block_id : {}",
                                       poet2_util::to_hex_string(&block.block_id));
                                service.check_block(block.block_id);
                            } else {
                                debug!("Failed consensus check for block_id : {}",
                                       poet2_util::to_hex_string(&block.block_id));
                                service.fail_block(block.block_id);
                            }
                        }

                        // When a block has passed validator checks
                        Update::BlockValid(block_id) => {
                            info!("BlockValid :: Checking and resolving fork for block_id : {}",
                                  poet2_util::to_hex_string(&block_id));
                            let new_block_won = fork_resolver::resolve_fork(
                                &mut service,
                                &mut state_store,
                                block_id, claim_wait_time, );
                            if new_block_won {
                                is_published_at_height = true;
                            }
                        }

                        // The chain head was updated, so abandon the
                        // block in progress and start a new one.
                        Update::BlockCommit(new_chain_head_blockid) => {
                            info!("BlockCommit :: Chain head updated to {}, abandoning block in progress",
                                  poet2_util::to_hex_string(&new_chain_head_blockid));

                            service.cancel_block();

                            // Need to get wait_time from certificate
                            is_published_at_height = false;
                            start = Instant::now();
                            let chain_head_block = service.get_chain_head();
                            wait_time = Duration::from_secs(service.get_wait_time(
                                &chain_head_block,
                                validator_id.as_str(), &poet_pub_key));

                            claim_wait_time = wait_time.as_secs();
                            service.initialize_block(Some(new_chain_head_blockid));
                        }

                        // Block is invalid 
                        Update::BlockInvalid(block_id) => {
                            info!("BlockInvalid :: Invalid block received with block id : {:?}",
                                  block_id);
                        }
                        _ => {}
                    }
                }

                Err(RecvTimeoutError::Disconnected) => {
                    error!("Disconnected from validator");
                    return Err(Error::UnknownPeer("Validator got disconnected.".to_string()));
                }

                Err(RecvTimeoutError::Timeout) => {}
            }

            if !is_published_at_height && Instant::now().duration_since(start) > wait_time {
                let cur_chain_head = service.get_chain_head();
                info!("Timer expired -- publishing block");
                debug!("Wait time was : {:?} for chain head: {}", wait_time,
                       poet2_util::to_hex_string(&cur_chain_head.block_id));

                let summary = service.summarize_block();
                let consensus: String = service.create_consensus(&summary,
                                                                 cur_chain_head,
                                                                 wait_time.as_secs());

                service.finalize_block(consensus.as_bytes());
                is_published_at_height = true;
            }
        }
    }

    fn version(&self) -> String {
        "2.0".into()
    }

    fn name(&self) -> String {
        "PoET".into()
    }
}

fn create_lmdb_context() -> Result<lmdb::LmdbContext, CliError> {
    let path_config = config::get_path_config();
    let statestore_path = &path_config.data_dir.join(config::get_filename());

    lmdb::LmdbContext::new(statestore_path, 1, None)
        .map_err(|err| CliError::EnvironmentError(format!("{}", err)))
}

fn open_statestore(ctx: &lmdb::LmdbContext) -> Result<ConsensusStateStore, CliError> {
    let statestore_db = lmdb::LmdbDatabase::new(
        ctx,
        &["index_consensus_state"],
    ).map_err(|err| CliError::EnvironmentError(format!("{}", err)))?;

    Ok(ConsensusStateStore::new(statestore_db))
}
