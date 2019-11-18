/*
 Copyright 2019 Intel Corporation
 Copyright 2020 Walmart Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
------------------------------------------------------------------------------
*/

use crate::sgx_structs::{
    sgx_struct_error::SgxStructError,
    sgx_struct_serde::{parse_from_bytes, serialize_to_bytes, SgxSerdeEndian},
    SgxStruct,
};

const STRUCT_SIZE: usize = 32;
const DEFAULT_VALUE: u8 = 0;
const ENDIANNESS: SgxSerdeEndian = SgxSerdeEndian::LittleEndian;

/// Provide a wrapper around sgx_measurement_t
///
/// #define SGX_HASH_SIZE 32
///
/// typedef struct _sgx_measurement_t
/// {
///     uint8_t m[SGX_HASH_SIZE];
/// } sgx_measurement_t;
///
/// See: https://01.org/sites/default/files/documentation/
///     intel_sgx_sdk_developer_reference_for_linux_os_pdf.pdf
#[derive(Serialize, Deserialize)]
pub struct SgxMeasurement {
    m: [u8; STRUCT_SIZE],
}

impl SgxMeasurement {
    pub fn m(&self) -> [u8; STRUCT_SIZE] {
        self.m
    }
}

impl SgxStruct for SgxMeasurement {
    /// Create an instance of SgxMeasurements with default value
    fn default() -> SgxMeasurement {
        SgxMeasurement {
            m: [DEFAULT_VALUE; STRUCT_SIZE],
        }
    }

    /// Serializes a object representing an SGX structure to bytes laid out in its corresponding
    /// C/C++ format.
    ///
    /// NOTE: If len(self.m) is less than self.STRUCT_SIZE, the resulting bytes will be padded
    /// with binary zero (\x00). If len(self.m) is greater than self.STRUCT_SIZE, the resulting
    /// bytes will be truncated to self.STRUCT_SIZE.
    fn serialize_to_bytes(&self) -> Result<Vec<u8>, SgxStructError> {
        serialize_to_bytes(&ENDIANNESS, &self.m)
    }

    /// Parses a byte array and creates the Sgx* object corresponding to the C/C++ struct.
    fn parse_from_bytes(
        &mut self,
        raw_buffer: &[u8],
    ) -> Result<(), SgxStructError> {
        let sgx_measurement: SgxMeasurement =
            match parse_from_bytes(&ENDIANNESS, raw_buffer) {
                Ok(result) => result,
                Err(err) => return Err(err),
            };
        self.m = sgx_measurement.m;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;

    #[test]
    fn test_parse_from_bytes() {
        let m = rand::thread_rng().gen::<[u8; super::STRUCT_SIZE]>();
        let mut sgx_structure: SgxMeasurement = SgxMeasurement::default();
        match sgx_structure.parse_from_bytes(&m) {
            Err(_) => assert!(false),
            Ok(_) => assert_eq!(m, sgx_structure.m),
        }
    }
}
