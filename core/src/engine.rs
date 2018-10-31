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
extern crate log;
extern crate log4rs;
 
use std::cmp;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;
use std::time::Instant;

use check_consensus as czk;
use consensus_state_store::ConsensusStateStore;
use database::config;
use database::lmdb;
use database::CliError;
use fork_resolver;
use poet2_util;
use sawtooth_sdk::consensus::{engine::*, service::Service};
use service::Poet2Service;
use settings_view::Poet2SettingsView;

pub struct Poet2Engine {
}

impl Poet2Engine {
    pub fn new() -> Self {
        Poet2Engine {}
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

        let validator_id = Vec::from(startup_state.local_peer_info.peer_id);
        let mut chain_head = startup_state.chain_head;

        let mut service = Poet2Service::new(service);

        let mut lmdb_ctx = create_lmdb_context().unwrap();
        let mut state_store = open_statestore(&lmdb_ctx).unwrap();

        let mut is_published_at_height = false;

        let mut start = Instant::now();

        service.enclave.initialize_enclave();
        service.enclave.create_signup_info(&validator_id);

        let (poet_pub_key, enclave_quote) = service.enclave.get_signup_parameters();

        let mut wait_time =  Duration::from_secs(service.get_wait_time(chain_head.clone(), &validator_id, &poet_pub_key));
        let mut prev_wait_time = 0;

        let mut poet2_settings_view = Poet2SettingsView::new();
        poet2_settings_view.init(chain_head.block_id.clone(), &mut service);

        service.initialize_block(None);

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
                        Update::BlockNew(block) => {
                            info!("Checking consensus data: {:?}", block);

                            if czk::check_consensus(block.clone(), &mut service, &validator_id, &poet_pub_key) {
                                info!("Passed consensus check: {:?}", block);
                                service.check_block(block.clone().block_id);
                                // Retain the block in static scope here for
                                // checks during fork resolution
                            } else {
                                info!("Failed consensus check: {:?}", block);
                                service.fail_block(block.block_id);
                            }
                        },

                        Update::BlockValid(block_id) => {
                            let new_block_won = fork_resolver::resolve_fork(
                                                    &mut service,
                                                    &mut state_store,
                                                    block_id, prev_wait_time,);
                            if new_block_won {
                                is_published_at_height = true;
                            }
                        },

                        // The chain head was updated, so abandon the
                        // block in progress and start a new one.
                        Update::BlockCommit(new_chain_head_blockid) => {
                            info!(
                                "Chain head updated to {:?}, abandoning block in progress",
                                new_chain_head_blockid
                            );

                            service.cancel_block();

                            is_published_at_height = false;
                            start = Instant::now();
                            let chain_head_block = service.get_chain_head();
                            wait_time = Duration::from_secs(service.get_wait_time(chain_head_block.clone(), &validator_id, &poet_pub_key));

                            service.initialize_block(Some(new_chain_head_blockid));
                        },

                        Update::PeerMessage(message, sender_id)
                            => match ResponseMessage::from_str(
                            message.message_type.as_ref(),
                        ).unwrap()
                        {
                            ResponseMessage::Published => {
                                let block_id = BlockId::from(message.content);
                                info!(
                                    "Received block published message from {:?}: {:?}",
                                    sender_id, block_id
                                );
                            }

                            ResponseMessage::Received => {
                                let block_id = BlockId::from(message.content);
                                info!(
                                    "Received block received message from {:?}: {:?}",
                                    sender_id, block_id
                                );
                                service.send_block_ack(sender_id, block_id);
                            }

                            ResponseMessage::Ack => {
                                let block_id = BlockId::from(message.content);
                                info!("Received ack message from {:?}: {:?}",
                                                         sender_id, block_id);
                            }
                        },

                        Update::BlockInvalid(block_id) => {
                            info!("Invalid block received with block id : {:?}",
                                                                      block_id);
                        },
                        _ => {}
                    }
                }

                Err(RecvTimeoutError::Disconnected) => {
                    error!("Disconnected from validator");
                    return Err(Error::UnknownPeer(format!("Validator got disconnected.")));
                }

                Err(RecvTimeoutError::Timeout) => {}
            }

            if !is_published_at_height && Instant::now().duration_since(start) > wait_time {
                let cur_chain_head = service.get_chain_head();
                info!("Timer expired -- publishing block");
                debug!("wait time was : {:?} for chain head: {:?}", wait_time, cur_chain_head.clone());

                let summary = service.summarize_block();
                let consensus: String = service.create_consensus(summary,
                                                                 cur_chain_head.clone(),
                                                                 wait_time.as_secs());

                let new_block_id = service.finalize_block(consensus.as_bytes().to_vec());
                service.broadcast(new_block_id.to_vec());

                let new_chain_head = service.get_block(new_block_id).unwrap();
                prev_wait_time = wait_time.as_secs();
                wait_time = Duration::from_secs(service.get_wait_time(new_chain_head, &validator_id, &poet_pub_key));
                info!("New wait time is : {:?}",wait_time);

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

pub enum ResponseMessage {
    Ack,
    Published,
    Received,
}

impl FromStr for ResponseMessage {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ack" => Ok(ResponseMessage::Ack),
            "published" => Ok(ResponseMessage::Published),
            "received" => Ok(ResponseMessage::Received),
            _ => Err("Invalid message type"),
        }
    }
}
