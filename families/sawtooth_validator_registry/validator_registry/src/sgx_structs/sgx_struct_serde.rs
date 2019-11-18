/*
 * Copyright 2019 Intel Corporation
 * Copyright 2020 Walmart Inc.
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

use crate::sgx_structs::sgx_struct_error::SgxStructError;
use bincode::Config;
use serde::{Deserialize, Serialize};

/// Represents endianness for serialization and deserialization.
/// Use or Set the appropriate configuration.
pub(crate) enum SgxSerdeEndian {
    LittleEndian,
    // Other variants that can be used are
    // BigEndian,
    // NativeEndian,
}

/// Helper method to return the configuration
impl SgxSerdeEndian {
    fn get_config(&self) -> Config {
        let mut config = bincode::config();
        match *self {
            SgxSerdeEndian::LittleEndian => config.little_endian(),
            // Other variants are unused
        };
        config
    }
}

/// Accept Endianness information for serializing the data
pub(crate) fn serialize_to_bytes<T: Serialize>(
    endianness: &SgxSerdeEndian,
    sgx_struct_data: &T,
) -> Result<Vec<u8>, SgxStructError> {
    let configuration = endianness.get_config();
    match configuration.serialize(sgx_struct_data) {
        Ok(result) => Ok(result),
        Err(err) => Err(SgxStructError::from(err)),
    }
}

/// Accept Endianness information for deserializing the data
pub(crate) fn parse_from_bytes<'a, T: Deserialize<'a>>(
    endianness: &SgxSerdeEndian,
    raw_buffer: &'a [u8],
) -> Result<T, SgxStructError> {
    let configuration = endianness.get_config();
    match configuration.deserialize(raw_buffer) {
        Ok(data) => Ok(data),
        Err(err) => Err(SgxStructError::from(err)),
    }
}
