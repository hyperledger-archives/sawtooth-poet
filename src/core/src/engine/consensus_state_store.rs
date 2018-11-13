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

use protobuf;
use engine::consensus_state::ConsensusState;
use sawtooth_sdk::consensus::engine::BlockId;
use database::lmdb::{LmdbContext, LmdbDatabase};
use database::DatabaseError;
use bincode::{serialize, deserialize};

#[derive(Debug)]
pub enum ConsensusStateStoreError {
    Error(String),
    UnknownConsensusState,
}

pub struct ConsensusStateStore<'a> {
    consensus_state_db: LmdbDatabase<'a>,
}

impl<'a> ConsensusStateStore<'a> {
    pub fn new(db: LmdbDatabase<'a>) -> Self {
        ConsensusStateStore { consensus_state_db:db, }
    }
    pub fn get( &self, block_id: BlockId, ) ->
        Result<Box<ConsensusState>, DatabaseError> {

        let reader = self.consensus_state_db.reader()?;
        let state = reader.get(&block_id).ok_or_else(|| {
            DatabaseError::NotFoundError(format!("State not found: {:?}", block_id))
        })?;
        debug!("Found state for block_id : {:?}", block_id);
        let consensus_state:ConsensusState = deserialize(&state).map_err(|err| {
            DatabaseError::CorruptionError(format!(
                "Could not interpret stored data as a block: {}",
                    err
                )
            )
        })?;
        Ok(Box::new(consensus_state.clone()))
    }

    pub fn delete(&mut self, block_id: BlockId) -> Result<(), DatabaseError>{
        let mut writer = self.consensus_state_db.writer()?;
        writer.delete(&Vec::from(block_id))?;

        Ok(())
    }

    pub fn put(&mut self, block_id: BlockId, consensus_state: ConsensusState) -> Result<(), DatabaseError>{
        let mut writer = self.consensus_state_db.writer()?;
        let serialized_state = serialize(&consensus_state).map_err(|err| {
            DatabaseError::WriterError(format!("Failed to serialize state: {}", err))
        })?;
        writer.put(&Vec::from(block_id), &serialized_state)?;
        Ok(())
    }
}
