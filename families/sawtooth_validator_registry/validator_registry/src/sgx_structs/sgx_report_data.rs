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

pub const STRUCT_SIZE: usize = 64;
pub const DEFAULT_VALUE: u8 = 0;
const ENDIANNESS: SgxSerdeEndian = SgxSerdeEndian::LittleEndian;

big_array! { BigArray; }

/// Provide a wrapper around sgx_report_data_t
///
/// #define SGX_REPORT_DATA_SIZE 64
///
/// typedef struct _sgx_report_data_t
/// {
///     uint8_t d[SGX_REPORT_DATA_SIZE];
/// } sgx_report_data_t;
///
/// See: https://01.org/sites/default/files/documentation/
///     intel_sgx_sdk_developer_reference_for_linux_os_pdf.pdf
#[derive(Serialize, Deserialize)]
pub struct SgxReportData {
    #[serde(with = "BigArray")]
    d: [u8; STRUCT_SIZE],
}

impl SgxReportData {
    pub fn d(&self) -> [u8; STRUCT_SIZE] {
        self.d
    }
}

impl SgxStruct for SgxReportData {
    /// Create an instance of SgxReportData with default value
    fn default() -> SgxReportData {
        SgxReportData {
            d: [DEFAULT_VALUE; STRUCT_SIZE],
        }
    }

    /// Serializes a object representing an SGX structure to bytes
    /// laid out in its corresponding C/C++ format.
    ///
    /// NOTE: If len(self.d) is less than self.STRUCT_SIZE,
    /// the resulting bytes will be padded with binary zero (\x00).
    /// If len(self.d) is greater than self.STRUCT_SIZE,
    /// the resulting bytes will be truncated to self.STRUCT_SIZE.
    fn serialize_to_bytes(&self) -> Result<Vec<u8>, SgxStructError> {
        serialize_to_bytes(&ENDIANNESS, &self)
    }

    /// Parses a byte array and creates the Sgx* object corresponding
    /// to the C/C++ struct.
    fn parse_from_bytes(
        &mut self,
        raw_buffer: &[u8],
    ) -> Result<(), SgxStructError> {
        let sgx_report_data: SgxReportData =
            match parse_from_bytes(&ENDIANNESS, raw_buffer) {
                Ok(sgx_report_data) => sgx_report_data,
                Err(err) => return Err(err),
            };
        self.d = sgx_report_data.d;
        Ok(())
    }
}
