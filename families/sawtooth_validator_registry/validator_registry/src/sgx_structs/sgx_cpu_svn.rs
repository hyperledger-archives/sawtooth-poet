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

const STRUCT_SIZE: usize = 16;
const DEFAULT_VALUE: u8 = 0;
const ENDIANNESS: SgxSerdeEndian = SgxSerdeEndian::LittleEndian;

/// Provide a wrapper around sgx_cpu_svn_t
///
/// #define SGX_CPUSVN_SIZE 16
/// typedef struct _sgx_cpu_svn_t
/// {
///     uint8_t svn[SGX_CPUSVN_SIZE];
/// } sgx_cpu_svn_t;
/// See: https://01.org/sites/default/files/documentation/
///         intel_sgx_sdk_developer_reference_for_linux_os_pdf.pdf
#[derive(Serialize, Deserialize)]
pub struct SgxCpuSvn {
    svn: [u8; STRUCT_SIZE],
}

impl SgxStruct for SgxCpuSvn {
    /// Create an instance of SgxCpuSvn with default value
    fn default() -> SgxCpuSvn {
        SgxCpuSvn {
            svn: [DEFAULT_VALUE; STRUCT_SIZE],
        }
    }

    /// Serializes a object representing an SGX structure to bytes
    /// laid out in its corresponding C/C++ format.
    ///
    /// NOTE: If len(self.svn) is less than self.STRUCT_SIZE,
    /// the resulting bytes will be padded with binary zero (\x00).
    /// If len(self.svn) is greater than self.STRUCT_SIZE,
    /// the resulting bytes will be truncated to self.STRUCT_SIZE.
    fn serialize_to_bytes(&self) -> Result<Vec<u8>, SgxStructError> {
        serialize_to_bytes(&ENDIANNESS, &self.svn)
    }

    /// Parses a byte array and creates the Sgx* object corresponding
    /// to the C/C++ struct.
    fn parse_from_bytes(
        &mut self,
        raw_buffer: &[u8],
    ) -> Result<(), SgxStructError> {
        match parse_from_bytes(&ENDIANNESS, raw_buffer) {
            Ok(svn) => {
                self.svn = svn;
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_parse_from_bytes() {
        let svn = rand::thread_rng().gen::<[u8; super::STRUCT_SIZE]>();
        let mut sgx_structure: SgxCpuSvn = SgxCpuSvn::default();
        match sgx_structure.parse_from_bytes(&svn) {
            Err(_) => assert!(false),
            Ok(_) => assert_eq!(svn, sgx_structure.svn),
        }
    }
}
