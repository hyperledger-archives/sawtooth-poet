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
use enclave_sgx::WaitCertificate;
use std::collections::VecDeque;
use std::collections::HashMap;
use serde_json;

/*
*  The validator state represents the state for a single
*  validator at a point in time.  A validator state object contains:
*  key_block_claim_count (int): The number of blocks that the validator has
*  claimed using the current PoET public key
*  poet_public_key (str): The current PoET public key for the validator
*  total_block_claim_count (int): The total number of the blocks that the
*      validator has claimed
*
*/
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ValidatorState {
    key_block_claim_count : u64,
    poet_public_key : String,
    total_block_claim_count: u64
}

/*
* The population sample represents the information
* we need to create the population estimate, which in turn is used to compute
* the local mean.  A population sample object contains:
* wait_time (float): The duration from a wait certificate/timer
* local_mean (float): The local mean from a wait certificate/timer
*/

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct PopulationSample {
    wait_time: u64,
    local_mean: f64
}

/*
*
* The population estimate represents what we need
* to help in computing zTest results.  A population estimate object contains:
*
* population_estimate (float): The population estimate for the corresponding
*     block
* previous_block_id (str): The ID of the block previous to the one that this
*     population estimate corresponds to
* validator_id (str): The ID of the validator that won the corresponding
*     block
*
*/
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct EstimateInfo {
    pub population_estimate : f64,
    // Needs to be of type BlockId but encapsulating structure is required to 
    // to be serializeable & BlockId is not at the sdk
    pub previous_block_id: String,//BlockId,
    pub validator_id: String
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ConsensusState {
    pub population_sample : PopulationSample,
    pub estimate_info : EstimateInfo,
    pub population_estimate_cache : HashMap<String, EstimateInfo>,
    pub total_block_claim_count: u64,
    pub validators: HashMap<String, ValidatorState>,
    pub aggregate_chain_clock: u64,
    pub aggregate_local_mean: f64,
    pub population_samples: VecDeque< PopulationSample>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ValidatorInfo{
    // Needs to be of type PeerId but encapsulating structure is required to 
    // to be serializeable & PeerId is not at the sdk
    id: String,//PeerId,
    poet_public_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct PoetSettingsView{
    population_estimate_sample_size: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct BlockInfo{
    wait_certificate: Option<WaitCertificate>,
    validator_info: Option<ValidatorInfo>,
    poet_settings_view: Option<PoetSettingsView>,
}

impl PartialEq for BlockInfo{
    fn eq( &self, other: &BlockInfo) -> bool {
        let self_ = self.clone();
        let other_ = other.clone();


        if (((self.wait_certificate.is_some() && other.wait_certificate.is_some()) 
            && (self_.wait_certificate.unwrap() == other_.wait_certificate.unwrap()))
          || (self.wait_certificate.is_none() && other.wait_certificate.is_none())) 
        && (((self.validator_info.is_some() && other.validator_info.is_some()) 
            && (self_.validator_info.unwrap() == other_.validator_info.unwrap()))
          || (self.validator_info.is_none() && other.validator_info.is_none())) 
        && (((self.poet_settings_view.is_some() && other.poet_settings_view.is_some()) 
            && (self_.poet_settings_view.unwrap() == other_.poet_settings_view.unwrap()))
          || (self.poet_settings_view.is_none() && other.poet_settings_view.is_none())) 
        
           { true }
        else    
           { false }
    }
}

#[derive(Clone, Default, Debug)]
struct Entry{
  key: BlockId,
  value: BlockInfo,
}

impl ConsensusState{

    pub fn consensus_state_for_block_id(&mut self, block_id: BlockId, svc: &mut Poet2Service) -> Option<ConsensusState>{
       let mut previous_wait_certificate: Option<WaitCertificate> = None;
       let mut consensus_state: Option<ConsensusState> = None;
       let mut blocks: Vec<Entry> = Vec::new();
       let mut current_id = block_id;
       loop{
         let block_ = svc.get_block(&current_id);
         let block: Block;
         if block_.is_ok(){
           block = block_.unwrap();
         }
         else{
           break;
         }
         /*consensus_state = consensus_state_store.get(current_id.clone());
         if consensus_state != None{
           break
         }*/
         let payload_vec = block.payload;
         let payload_str  = String::from_utf8(payload_vec).expect("Found Invalid UTF-8"); 
         let wait_certificate = Some(serde_json::from_str(&payload_str).unwrap());
         if  wait_certificate.is_some() {
           //TODO
         }
         else if blocks.is_empty() || previous_wait_certificate.is_some(){
            blocks.push(Entry{ key: current_id.clone(), value: BlockInfo{ wait_certificate: None, validator_info: None, poet_settings_view: None} });           
         }
         previous_wait_certificate = wait_certificate.clone();
         current_id = block.previous_id;
         //let mut consensus_state = consensus_state_store_.get(current_id.clone());
         if consensus_state.is_none(){
           consensus_state = Some(ConsensusState::default());
         }
         for entry in blocks.iter().rev(){
           let mut val = &entry.value;
           if val.wait_certificate.is_none(){
             consensus_state = Some(ConsensusState::default());
           } 
           else{
             self.validator_did_claim_block(&(val.clone().validator_info.unwrap()), &(val.clone().wait_certificate.unwrap()), &(val.clone().poet_settings_view.unwrap()));
           } 
         }
       }
       consensus_state 
    }

    pub fn validator_did_claim_block(&mut self, validator_info: &ValidatorInfo, wait_certificate: &WaitCertificate, poet_settings_view: &PoetSettingsView ) -> (){
      self.aggregate_local_mean += 5.5_f64; //wait_certificate.local_mean;
      self.total_block_claim_count += 1;
      self.population_samples.push_back( PopulationSample{ wait_time: wait_certificate.wait_time , local_mean: 5.5_f64}); //wait_certificate.local_mean}); 
      while self.population_samples.len() > poet_settings_view.population_estimate_sample_size{
        self.population_samples.pop_front();
      }
       let validator_state = self.get_validator_state(validator_info.clone());
       let total_block_claim_count = validator_state.total_block_claim_count + 1;
       let key_block_claim_count = if validator_info.poet_public_key == validator_state.poet_public_key {
                                                validator_state.key_block_claim_count + 1
                                       } 
                                       else{
                                           1
                                       };
       let peerid_vec = Vec::from(validator_info.clone().id);
       let peerid_str = String::from_utf8(peerid_vec).expect("Found Invalid UTF-8");
       self.validators.insert(peerid_str, ValidatorState{ key_block_claim_count: key_block_claim_count, poet_public_key: validator_info.clone().poet_public_key, total_block_claim_count: total_block_claim_count});

   }

   pub fn get_validator_state(&mut self,  validator_info: ValidatorInfo) -> Box<ValidatorState>{
     let peerid_vec = Vec::from(validator_info.clone().id);
     let peerid_str = String::from_utf8(peerid_vec).expect("Found Invalid UTF-8");
     let validator_state = self.validators.get(&peerid_str);
     let val_state = ValidatorState{ key_block_claim_count: 0, poet_public_key: validator_info.clone().poet_public_key, total_block_claim_count: 0};
     if validator_state.is_none(){
      return Box::new(val_state); 
     }
     Box::new(validator_state.unwrap().clone())
   }
}

