/*
 * Copyright 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file expect in compliance with the License.
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
use database::lmdb;
use database::lmdb::{LmdbContext, LmdbDatabase};
use database::{DatabaseError, CliError};
use bincode::{serialize, deserialize};
use poet2_util;

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
            DatabaseError::NotFoundError(format!("State not found for
                block_id: {}",poet2_util::to_hex_string(&block_id)))
        })?;
        debug!("Found state for block_id : {}", poet2_util::to_hex_string(&block_id));
        let consensus_state:ConsensusState = deserialize(&state).map_err(|err| {
            DatabaseError::CorruptionError(format!(
                "Error in deserializing consensus state : {}",
                    err
                )
            )
        })?;
        Ok(Box::new(consensus_state.clone()))
    }

    pub fn delete(&mut self, block_id: BlockId) -> Result<(), DatabaseError>{
        let mut writer = self.consensus_state_db.writer()?;
        writer.delete(&Vec::from(block_id.clone()))?;
        writer.commit().expect(&format!("Failed to commit state deletion for block_id : {}",
            poet2_util::to_hex_string(&block_id)));
        debug!("Deleted state for block_id : {}", poet2_util::to_hex_string(&block_id));
        Ok(())
    }

    pub fn put(&mut self, block_id: BlockId, consensus_state: ConsensusState) -> Result<(), DatabaseError>{
        let mut writer = self.consensus_state_db.writer()?;
        let serialized_state = serialize(&consensus_state).map_err(|err| {
            DatabaseError::WriterError(format!("Failed to serialize state: {}", err))
        })?;
        writer.put(&Vec::from(block_id.clone()), &serialized_state)?;
        writer.commit().expect(&format!("Failed to commit state write to db for block_id : {}",
            poet2_util::to_hex_string(&block_id)));
        debug!("Stored state for block_id : {}", poet2_util::to_hex_string(&block_id));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use database::config;

    /// Asserts that there are COUNT many objects in DB.
    fn assert_database_db_count(count: usize, db: &LmdbDatabase) {
        let reader = db.reader().unwrap();

        assert_eq!(reader.count().unwrap(), count,);
    }

    /// Asserts that there are are COUNT many objects in DB's INDEX.
    fn assert_index_count(index: &str, count: usize, db: &LmdbDatabase) {
        let reader = db.reader().unwrap();

        assert_eq!(reader.index_count(index).unwrap(), count,);
    }

    /// Asserts that KEY is associated with VAL in DB.
    fn assert_key_value(key: u8, val: u8, db: &LmdbDatabase) {
        let reader = db.reader().unwrap();

        assert_eq!(reader.get(&[key]).unwrap(), [val],);
    }

    /// Asserts that KEY is associated with VAL in DB's INDEX.
    fn assert_index_key_value(index: &str, key: u8, val: u8, db: &LmdbDatabase) {
        let reader = db.reader().unwrap();

        assert_eq!(reader.index_get(index, &[key]).unwrap().unwrap(), [val],);
    }

    /// Asserts that KEY is not in DB.
    fn assert_not_in_database_db(key: u8, db: &LmdbDatabase) {
        let reader = db.reader().unwrap();

        assert!(reader.get(&[key]).is_none());
    }

    /// Asserts that KEY is not in DB's INDEX.
    fn assert_not_in_index(index: &str, key: u8, db: &LmdbDatabase) {
        let reader = db.reader().unwrap();

        assert!(reader.index_get(index, &[key]).unwrap().is_none());
    }

    fn create_context() -> Result<lmdb::LmdbContext, CliError> {
        let path_config = config::get_path_config();
        let statestore_path = &path_config.data_dir.join(config::get_filename());
        assert!(statestore_path.exists());

        lmdb::LmdbContext::new(statestore_path, 1, None)
            .map_err(|err| CliError::EnvironmentError(format!("{}", err)))
    }

    #[test]
    fn test_state_store_get() {

        let mut ctx = create_context().unwrap();
        let statestore_db = lmdb::LmdbDatabase::new(
            &ctx,
            &["index_consensus_state"],
        ).map_err(|err| CliError::EnvironmentError(format!("{}", err))).unwrap();

        let mut state_store = ConsensusStateStore::new(statestore_db);

        // Taking random u8 vector as block_id
        assert!(state_store.get(BlockId::from(vec![11])).is_err());
        state_store.put( BlockId::from(vec![11]), ConsensusState::default() );

        assert!(state_store.get(BlockId::from(vec![11])).is_ok());
        //cleanup
        state_store.delete( BlockId::from(vec![11]) );
        assert!(state_store.get(BlockId::from(vec![11])).is_err());
    }

    #[test]
    fn test_state_store_put() {

        let mut ctx = create_context().unwrap();
        let statestore_db = lmdb::LmdbDatabase::new(
            &ctx,
            &["index_consensus_state"],
        ).map_err(|err| CliError::EnvironmentError(format!("{}", err))).unwrap();

        let mut state_store = ConsensusStateStore::new(statestore_db);

        // Taking random u8 vector as block_id
        assert!(state_store.get(BlockId::from(vec![13])).is_err());
        state_store.put( BlockId::from(vec![13]), ConsensusState::default() );

        assert!(state_store.get(BlockId::from(vec![13])).is_ok());
        assert_eq!(*state_store.get(BlockId::from(vec![13])).unwrap(),
            ConsensusState::default());
        //cleanup
        state_store.delete( BlockId::from(vec![13]) );
        assert!(state_store.get(BlockId::from(vec![13])).is_err());
    }

    #[test]
    fn test_state_store_delete() {

        let mut ctx = create_context().unwrap();
        let statestore_db = lmdb::LmdbDatabase::new(
            &ctx,
            &["index_consensus_state"],
        ).map_err(|err| CliError::EnvironmentError(format!("{}", err))).unwrap();

        let mut state_store = ConsensusStateStore::new(statestore_db);

        // Taking random u8 vector as block_id
        state_store.put( BlockId::from(vec![14]), ConsensusState::default() );
        state_store.put( BlockId::from(vec![15]), ConsensusState::default() );

        assert_eq!(*state_store.get(BlockId::from(vec![14])).unwrap(),
            ConsensusState::default());
        assert_eq!(*state_store.get(BlockId::from(vec![15])).unwrap(),
            ConsensusState::default());

        state_store.delete( BlockId::from(vec![14]) );
        assert!(state_store.get(BlockId::from(vec![14])).is_err());
        assert!(state_store.get(BlockId::from(vec![15])).is_ok());
        //cleanup
        state_store.delete( BlockId::from(vec![15]) );
        assert!(state_store.get(BlockId::from(vec![15])).is_err());
    }
}
