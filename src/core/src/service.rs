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

use sawtooth_sdk::consensus::{engine::*,service::Service};
use std::thread::sleep;
use std::time;
use std::time::Instant;
use poet2_util;
use std::collections::HashMap;
use serde_json;
use enclave_sgx::*;

pub struct Poet2Service {
    service: Box<Service>,
    init_wall_clock: Instant,
    chain_clock: u64,
    pub enclave: EnclaveConfig,
}

impl Poet2Service {
    pub fn new(service_: Box<Service>) -> Self {
        let now = Instant::now();
        Poet2Service { 
            service : service_,
            init_wall_clock : now,
            chain_clock : 0,
            enclave : EnclaveConfig::default(),
        }
    }

    pub fn get_chain_clock(&mut self) -> u64 {
        self.chain_clock
    }

    pub fn get_wall_clock(&mut self) -> u64 {
        self.init_wall_clock.elapsed().as_secs()
    }

    pub fn set_chain_clock(&mut self, new_cc : u64) {
        self.chain_clock = new_cc;
    }

    pub fn get_chain_head(&mut self) -> Block {
        debug!("Getting chain head");
        self.service
            .get_chain_head()
            .expect("Failed to get chain head")
    }

    pub fn get_block(&mut self, block_id: &BlockId) -> Result<Block, Error> {
        debug!("Getting block {:?}", block_id);
        let blocks = self.service
            .get_blocks(vec![block_id.clone()]); // clone needed as vector needs ownership
        match blocks {
            Err(err) => {
                warn!("Could not get a block with id {:?}", block_id);
                Err(Error::UnknownBlock(format!("Block not found for id {:?} {:?}", block_id, err)))
            }
            Ok(mut block_map) => {
                //remove from the returned hashmap to get value
                Ok(block_map.remove(block_id).unwrap())
            }
        }
    }

    pub fn initialize_block(&mut self, previous_id: Option<BlockId>) {
        debug!("Initializing block");
        self.service
            .initialize_block(previous_id)
            .expect("Failed to initialize block");
    }

    pub fn summarize_block(&mut self) -> Vec<u8> {
        debug!("Summarizing block");
        let mut summary = self.service.summarize_block();
        while let Err(Error::BlockNotReady) = summary {
           debug!("Block not ready to summarize");
           sleep(time::Duration::from_secs(1));
           summary = self.service.summarize_block();
        }
        summary.expect("Failed to summarize block")
    }

    pub fn finalize_block(&mut self, consensus: Vec<u8>) -> BlockId {
        debug!("Finalizing block");
        let mut block_id = self.service.finalize_block(consensus.clone());
        while let Err(Error::BlockNotReady) = block_id {
            warn!("Block not ready to finalize");
            sleep(time::Duration::from_secs(1));
            block_id = self.service.finalize_block(consensus.clone());
        }
        block_id.expect("Failed to finalize block")
    }

    pub fn check_block(&mut self, block_id: BlockId) {
        debug!("Checking block {:?}", block_id);
        self.service
            .check_blocks(vec![block_id])
            .expect("Failed to check block");
    }

    pub fn fail_block(&mut self, block_id: BlockId) {
        debug!("Failing block {:?}", block_id);
        self.service
            .fail_block(block_id)
            .expect("Failed to fail block");
    }

    pub fn ignore_block(&mut self, block_id: BlockId) {
        debug!("Ignoring block {:?}", block_id);
        self.service
            .ignore_block(block_id)
            .expect("Failed to ignore block")
    }

    pub fn commit_block(&mut self, block_id: BlockId) {
        debug!("Committing block {:?}", block_id);
        self.service
            .commit_block(block_id)
            .expect("Failed to commit block");
    }


    pub fn cancel_block(&mut self) {
        debug!("Cancelling block");
        //TODO Handle InvalidState better
        match self.service.cancel_block() {
            Ok(_) => {}
            Err(Error::InvalidState(_)) => {}
            Err(err) => {
                panic!("Failed to cancel block: {:?}", err);
            }
        };
    }

    pub fn broadcast(&mut self, payload: Vec<u8>) {
        debug!("Broadcasting payload");
        self.service
            .broadcast("published", payload)
            .expect("Failed to broadcast published block");
    }

    pub fn send_block_received(&mut self, block: &Block) {
        let block = block.clone();

        self.service
            .send_to(
                &PeerId::from(block.signer_id),
                "received",
                Vec::from(block.block_id),
            )
            .expect("Failed to send block received");
    }

    pub fn send_block_ack(&mut self, sender_id: PeerId, block_id: BlockId) {
        self.service
            .send_to(&sender_id, "ack", Vec::from(block_id))
            .expect("Failed to send block ack");
    }

    pub fn get_wait_time(&mut self, pre_chain_head: &Block, validator_id: &Vec<u8>,
                        poet_pub_key: &String) -> u64
    {
        let mut prev_wait_certificate = String::new();
        let mut prev_wait_certificate_sig = String::new();

        info!("Getting new wait time for block num {}", pre_chain_head.block_num);
        debug!("Getting new wait time for block id {} prev_id {}",
                   poet2_util::to_hex_string(&pre_chain_head.block_id),
                      poet2_util::to_hex_string(&pre_chain_head.previous_id));
        if pre_chain_head.block_num != 0_u64 { // non-genesis block
            let result =
                 poet2_util::payload_to_wc_and_sig(&pre_chain_head.payload);
            prev_wait_certificate = result.0;
            prev_wait_certificate_sig = result.1;
        }
        let duration64 = EnclaveConfig::initialize_wait_certificate(
                              self.enclave.enclave_id,
                              prev_wait_certificate,
                              prev_wait_certificate_sig,
                              &validator_id,
                              &poet_pub_key);

        let minimum_duration : f64 = 1.0_f64;
        let local_mean = 5.5_f64;
        let tagd = (duration64 as f64) / (u64::max_value() as f64);
        let mut wait_time = minimum_duration
                            - local_mean * tagd.log10();
        if wait_time as u64 == 0_u64 {
             wait_time = minimum_duration; 
        }
        return wait_time as u64;
    }

    pub fn get_settings(&mut self, block_id: BlockId, keys: Vec<String>)
         -> Result<HashMap<String, String>, Error> {
        let settings_result = self.service.get_settings(
            block_id,
            keys);
        settings_result
    }

    pub fn get_setting(&mut self, block_id: BlockId, key:String) -> String {
        let settings_result = self.service.get_settings(
            block_id,
            vec![
                    key.clone(),
                ],
        );

        if settings_result.is_ok() {
            settings_result.unwrap().remove(&key).unwrap()
        }
        else {
            error!("Could not get setting for key {}", key);
            String::from("")
        }
    }

    pub fn get_setting_from_head(&mut self, key:String) ->  String {
        let head_id:BlockId = self.get_chain_head().block_id;
        self.get_setting( head_id, key )
    }

    pub fn create_consensus(&mut self, summary: Vec<u8>, chain_head: Block, wait_time : u64) -> String {
        let mut wait_certificate = String::new();
        let mut wait_certificate_sig = String::new();

        if chain_head.block_num != 0_u64 { // not genesis block
            let result =
                 poet2_util::payload_to_wc_and_sig(&chain_head.payload);
            wait_certificate = result.0;
            wait_certificate_sig = result.1;
        }
        info!("Block id returned is {:?}",  poet2_util::to_hex_string(&chain_head.block_id));
        let (serial_cert, cert_signature) = EnclaveConfig::finalize_wait_certificate(
                self.enclave.enclave_id,
                wait_certificate,
                poet2_util::blockid_to_hex_string(chain_head.block_id),
                wait_certificate_sig, 
                poet2_util::to_hex_string(&summary),
                wait_time
            );

        let mut payload_to_send = serial_cert;
        payload_to_send.push_str("#");
        payload_to_send.push_str(&cert_signature); 
        return payload_to_send.clone();
    }

    pub fn verify_wait_certificate( &mut self, _block: &Block, previous_block: &Block, poet_pub_key: &String) -> bool {
        let block = _block.clone();
        let mut wait_cert_verify_status:bool = false;

        
        let (wait_cert, wait_cert_sign) = get_wait_cert_and_signature(&block);
        debug!("Serialized wait_cert : {:?}", &wait_cert);
        let deser_wait_cert:WaitCertificate = serde_json::from_str(&wait_cert).unwrap();

        let sig_verify_status = EnclaveConfig::verify_wait_certificate(self.enclave.enclave_id,
                                                            &poet_pub_key,
                                                            &wait_cert, &wait_cert_sign);

        debug!("sig_verify_status={:?}", sig_verify_status);

        let prev_id = poet2_util::blockid_to_hex_string(block.previous_id);
        let signer_id =poet2_util::to_hex_string(&block.signer_id.to_vec());
        let summary = poet2_util::to_hex_string(&block.summary);
        
        if (deser_wait_cert.prev_block_id == prev_id) &&
            (deser_wait_cert.block_number == block.block_num) &&
            (deser_wait_cert.block_summary == summary) &&
            (deser_wait_cert.validator_id == signer_id) &&
            sig_verify_status {
            
            if  block.block_num > 1 {
                let prev_block = previous_block.clone();
                let ( _ , prev_wait_cert_sig) = get_wait_cert_and_signature(&prev_block);
                if deser_wait_cert.prev_wait_cert_sig == prev_wait_cert_sig {
                    wait_cert_verify_status = true;
                }
            }
            else if block.block_num == 1 {
                wait_cert_verify_status = true;
            }
        }

        info!("Wait Certificate verification {}", if wait_cert_verify_status {"Passed"} else {"Failed"});
        wait_cert_verify_status
    }
}

pub fn get_wait_cert_and_signature(block: &Block) -> (String, String) {
        let payload = block.payload.clone();
        debug!("Extracted payload from block: {:?}", payload);
        let (wait_cert, wait_cert_sign) = poet2_util::payload_to_wc_and_sig(&payload);

        (wait_cert, wait_cert_sign)
    }


#[cfg(test)]
mod tests {
    use super::*;
    use rand;
    use rand::Rng;
    use std::default::Default;
    use zmq;
    use sawtooth_sdk::consensus::{zmq_service::ZmqService};
    use protobuf::{Message as ProtobufMessage};
    use protobuf;
    use sawtooth_sdk::messages::consensus::*;
    use sawtooth_sdk::messages::validator::{Message, Message_MessageType};
    use sawtooth_sdk::messaging::zmq_stream::ZmqMessageConnection;
    use sawtooth_sdk::messaging::stream::MessageConnection;
    fn generate_correlation_id() -> String {
        const LENGTH: usize = 16;
        rand::thread_rng().gen_ascii_chars().take(LENGTH).collect()
    }
    fn send_req_rep<I: protobuf::Message, O: protobuf::Message>(
        connection_id: &[u8],
        socket: &zmq::Socket,
        request: I,
        request_type: Message_MessageType,
        response_type: Message_MessageType,
    ) -> O {
        let correlation_id = generate_correlation_id();
        let mut msg = Message::new();
        msg.set_message_type(request_type);
        msg.set_correlation_id(correlation_id.clone());
        msg.set_content(request.write_to_bytes().unwrap());
        socket
            .send_multipart(&[connection_id, &msg.write_to_bytes().unwrap()], 0)
            .unwrap();
        let msg: Message =
            protobuf::parse_from_bytes(&socket.recv_multipart(0).unwrap()[1]).unwrap();
        assert!(msg.get_message_type() == response_type);
        protobuf::parse_from_bytes(&msg.get_content()).unwrap()
    }

    fn recv_rep<I: protobuf::Message, O: protobuf::Message>(
        socket: &zmq::Socket,
        request_type: Message_MessageType,
        response: I,
        response_type: Message_MessageType,
    ) -> (Vec<u8>, O) {
        let mut parts = socket.recv_multipart(0).unwrap();
        assert!(parts.len() == 2);

        let mut msg: Message = protobuf::parse_from_bytes(&parts.pop().unwrap()).unwrap();
        let connection_id = parts.pop().unwrap();
        assert!(msg.get_message_type() == request_type);
        let request: O = protobuf::parse_from_bytes(&msg.get_content()).unwrap();

        let correlation_id = msg.take_correlation_id();
        let mut msg = Message::new();
        msg.set_message_type(response_type);
        msg.set_correlation_id(correlation_id);
        msg.set_content(response.write_to_bytes().unwrap());
        socket
            .send_multipart(&[&connection_id, &msg.write_to_bytes().unwrap()], 0)
            .unwrap();

        (connection_id, request)
    }

    macro_rules! service_test {
        (
            $socket:expr,
            $rep:expr,
            $status:expr,
            $rep_msg_type:expr,
            $req_type:ty,
            $req_msg_type:expr
        ) => {
            let mut response = $rep;
            response.set_status($status);
            let (_, _): (_, $req_type) =
                recv_rep($socket, $req_msg_type, response, $rep_msg_type);
        };
    }

    #[test]
    fn test_service() {
        let ctx = zmq::Context::new();
        let socket = ctx.socket(zmq::ROUTER).expect("Failed to create context");
        socket
            .bind("tcp://127.0.0.1:*")
            .expect("Failed to bind socket");
        let addr = socket.get_last_endpoint().unwrap().unwrap();

        let svc_thread = ::std::thread::spawn(move || {
            let connection = ZmqMessageConnection::new(&addr);
            let (sender, _) = connection.create();
            let mut zmq_svc = ZmqService::new(
                sender,
                ::std::time::Duration::from_secs(10),
            );
            
                
            let mut svc = Poet2Service::new( Box::new(zmq_svc) );
            
            svc.initialize_block(Some(Default::default()));
        });
        service_test!(
            &socket,
            ConsensusInitializeBlockResponse::new(),
            ConsensusInitializeBlockResponse_Status::OK,
            Message_MessageType::CONSENSUS_INITIALIZE_BLOCK_RESPONSE,
            ConsensusInitializeBlockRequest,
            Message_MessageType::CONSENSUS_INITIALIZE_BLOCK_REQUEST
        );
    }
    
    #[test]
    fn test_dummy() {
        assert_eq!(4, 2+2);
    }
}
