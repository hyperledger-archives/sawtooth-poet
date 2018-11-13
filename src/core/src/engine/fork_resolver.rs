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
use sawtooth_sdk::consensus::{engine::*};
use service::Poet2Service;
use serde_json;
use engine::consensus_state::*;
use engine::consensus_state_store::ConsensusStateStore;
use poet2_util;
use enclave_sgx::WaitCertificate;

pub fn resolve_fork(service: &mut Poet2Service, state_store: &mut ConsensusStateStore,
        block_id: BlockId, mut claim_block_dur: u64) -> bool {

    let block_ = service.get_block(&block_id);
    let mut published = false;
    let chain_head = service.get_chain_head();

    if block_.is_ok(){

        let block = block_.unwrap();
        service.send_block_received(&block);

        let prev_block_ = service.get_block(&block.previous_id);

        info!(
            "Choosing between chain heads -- current: {:?} -- new: {:?}",
            chain_head, block
        );

        // Commiting or Resolving fork if one exists
        // Advance the chain if possible.

        let new_block_dur = get_cert_from(&block).wait_time;

        if claim_block_dur == 0 {
            claim_block_dur = new_block_dur;
        }
        // Current block points to current head
        // Check if block already claimed. Go on to
        // compare duration then. Accept one of them
        // and update it to be new chain head
        if block.block_num == (1 + chain_head.block_num)
              && block.previous_id == chain_head.block_id {

            debug!("New block duration {} Claim block duration {}",
                       new_block_dur, claim_block_dur);
            if new_block_dur <= claim_block_dur{
                info!("Discarding the block in progress.");
                service.cancel_block();
                published = true;
                info!("New block extends current chain. Committing {:?}", block);
                let agg_chain_clock = service.get_chain_clock() +
                    new_block_dur;
                let mut state = ConsensusState::default();
                state.aggregate_chain_clock = agg_chain_clock;
                state.estimate_info = EstimateInfo{
                    population_estimate : 0_f64,
                    previous_block_id   : poet2_util::to_hex_string(&Vec::from(block.previous_id)),
                    validator_id        : poet2_util::to_hex_string(&Vec::from(block.signer_id)),
                };
                debug!("Storing cummulative cc = {} for blockId : {:?}",
                    agg_chain_clock, block_id.clone());
                state_store.put(block_id.clone(), state);
                service.set_chain_clock(agg_chain_clock);
                service.commit_block(block_id);
            }
            else {
                info!("New block has larger duration. Failing {:?}", block);
                service.fail_block(block_id);
            }
        }

        // Check if the previous block is strictly in the
        // cache. If so, look for common ancestor and resolve fork.
        else if prev_block_.is_ok(){
            let prev_block = prev_block_.unwrap();

            if state_store.get(prev_block.block_id).is_err() {
                let mut cache_block = block.clone();
                let block_state;
                let mut block_state_;
                let cc_upto_head = service.get_chain_clock();
                let mut fork_cc:u64 = new_block_dur;
                let mut fork_len:u64 = 1;
                let mut cc_upto_ancestor = 0_u64;
                let mut ancestor_found:bool = false;
                info!("Looping over chain to find common ancestor.");

                loop {
                    let cache_block_ = service.get_block(&cache_block.previous_id);

                    // If block's previous not in cache or statestore,
                    // break from loop and send block to cache
                    if cache_block_.is_ok() {

                        cache_block = cache_block_.unwrap();
                        if cache_block.block_num == 0 {
                            debug!("Genesis reached while finding common ancestor.");
                            ancestor_found = true;
                            break;
                        }

                        // get cc from certificate in cache_block
                        let ancestor_cc = get_cert_from(&cache_block).wait_time;

                        // Assuming here that we have the consensus state
                        // for each block that has been committed into the chain.
                        // Parse blocks from cache & states from the statestore
                        // to find a common ancestor.
                        // Keep account of the chainclocks from cache.
                        // Once common ancestor is found, compare the
                        // chainclocks of the forks to choose a fork
                        block_state_ = state_store.get(cache_block.block_id.clone());
                        if block_state_.is_ok() {
                            // Found common ancestor
                            info!("Found a common ancestor at block {:?}",block.clone());
                            ancestor_found = true;
                            block_state = block_state_.unwrap();
                            cc_upto_ancestor = block_state.aggregate_chain_clock;
                            break;
                        }
                        fork_cc += ancestor_cc;
                        fork_len += 1;
                    }
                    else {
                        info!("Not a valid fork.");
                    }
                }
                let mut fork_won = false;
                let mut chain_cc:u64 = 0;
                if ancestor_found {
                    info!("Found a common ancestor. Comparing length.");
                    debug!("Chain clocks upto head = {}, upto common ancestor = {}",
                        cc_upto_head, cc_upto_ancestor);
                    chain_cc = cc_upto_head - cc_upto_ancestor;
                    let chain_len:u64 = chain_head.block_num - cache_block.block_num;
                    if chain_len > fork_len {
                        fork_won = false;
                    }
                    else if chain_len < fork_len {
                        fork_won = true;
                    }
                    // Fork lengths are equal
                    else {
                        if chain_cc == fork_cc {
                            fork_won = if get_cert_from(&block).duration_id
                                       <  get_cert_from(&chain_head).duration_id
                                       { true } else { false };
                        }
                        else {
                            fork_won = if fork_cc < chain_cc { true } else { false };
                        }
                    }
                }
                if fork_won {
                    info!("Discarding the block in progress.");
                    service.cancel_block();
                    published = true;
                    info!("Switching to fork.");
                    // fork_cc is inclusive of new block
                    let agg_chain_clock = cc_upto_ancestor + fork_cc;
                    let mut state = ConsensusState::default();
                    state.aggregate_chain_clock = agg_chain_clock;
                    debug!("Aggregate chain clock upto common ancestor = {}
                                Fork chain clock = {}. After switch aggregate = {}",
                                cc_upto_ancestor, fork_cc, agg_chain_clock);
                    debug!("Storing cummulative cc = {}", agg_chain_clock);
                    state.estimate_info = EstimateInfo{
                        population_estimate : 0_f64,
                        previous_block_id   : poet2_util::to_hex_string(&Vec::from(block.previous_id)),
                        validator_id        : poet2_util::to_hex_string(&Vec::from(block.signer_id)),
                    };
                    state_store.put(block_id.clone(), state);
                    service.set_chain_clock(agg_chain_clock);
                    service.commit_block(block_id);
                    // Mark all blocks upto common ancestor
                    // in the chain as invalid.
                    // Delete states for all blocks not in chain
                    let chain_len_to_delete = chain_head.block_num - cache_block.block_num;
                    delete_states_upto( cache_block.block_id , chain_head.clone().block_id,
                    chain_len_to_delete, service, state_store );
                }
                else {
                    info!("Not switching to fork");
                    service.ignore_block(block.block_id.clone());
                }
            }
        }
    }
    published
    // Fork Resolution done
}

fn delete_states_upto( ancestor: BlockId, head: BlockId, delete_len: u64,
                       service: &mut Poet2Service, state_store: &mut ConsensusStateStore ) -> ()
{
    let mut next = head;
    let mut count = 0_u64;
    loop {
        if ancestor == next || count >= delete_len {
            break;
        }
        count += 1;
        let state_ = state_store.get(next.clone());
        if state_.is_err() {
            debug!("State not found. Getting block via service.");
            let block_ = service.get_block(&next);
            if block_.is_ok(){
                let block = block_.unwrap();
                next = block.previous_id;
                continue;
            }
            break;
        }
        else {
            debug!("Deleting state for {:?}", next.clone());
            state_store.delete(next.clone());
            next = BlockId::from(state_.unwrap().estimate_info.previous_block_id.as_bytes().to_vec());
        }
    }
}

fn get_cert_from(block: &Block) -> WaitCertificate {
    let payload = block.payload.clone();
    debug!("Extracted payload from block: {:?}", payload.clone());
    let (wait_certificate, _) = poet2_util::payload_to_wc_and_sig(&payload);
    debug!("Serialized wait_cert : {:?}", &wait_certificate);
    serde_json::from_str(&wait_certificate).unwrap()
}
