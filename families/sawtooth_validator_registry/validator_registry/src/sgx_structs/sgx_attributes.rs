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

/// const STRUCT_SIZE: usize = 16;
const DEFAULT_VALUE: u64 = 0;
const ENDIANNESS: SgxSerdeEndian = SgxSerdeEndian::LittleEndian;

/// Provide a wrapper around sgx_attributes_t
///
/// typedef struct _attributes_t
/// {
///     uint64_t flags; /* 0 */
///     uint64_t xfrm;  /* 8 */
/// } sgx_attributes_t;
///
/// See: https://01.org/sites/default/files/documentation/
///     intel_sgx_sdk_developer_reference_for_linux_os_pdf.pdf
#[derive(Serialize, Deserialize)]
pub struct SgxAttributes {
    flags: u64,
    xfrm: u64,
}

impl SgxStruct for SgxAttributes {
    /// Create an instance of SgxAttributes with default value
    fn default() -> SgxAttributes {
        SgxAttributes {
            flags: DEFAULT_VALUE,
            xfrm: DEFAULT_VALUE,
        }
    }

    /// Serializes a object representing an SGX structure to bytes
    /// laid out in its corresponding C/C++ format.
    ///
    /// NOTE: All integer struct fields are serialized to little endian format
    fn serialize_to_bytes(&self) -> Result<Vec<u8>, SgxStructError> {
        let raw_data = (self.flags, self.xfrm);
        serialize_to_bytes(&ENDIANNESS, &raw_data)
    }

    /// Parses a byte array and creates the Sgx* object corresponding
    /// to the C/C++ struct.
    fn parse_from_bytes(
        &mut self,
        raw_buffer: &[u8],
    ) -> Result<(), SgxStructError> {
        match parse_from_bytes(&ENDIANNESS, raw_buffer) {
            Ok((flags, xfrm)) => {
                self.flags = flags;
                self.xfrm = xfrm;
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}
