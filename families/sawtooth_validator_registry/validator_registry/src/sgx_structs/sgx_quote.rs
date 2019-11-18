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
    sgx_basename::SgxBasename,
    sgx_report_body::SgxReportBody,
    sgx_struct_error::SgxStructError,
    sgx_struct_serde::{parse_from_bytes, serialize_to_bytes, SgxSerdeEndian},
    SgxStruct,
};

const FIXED_STRUCT_SIZE: usize = 432;
const EPID_GROUP_ID_SIZE: usize = 4;
const DEFAULT_VALUE: u8 = 0;
const DEFAULT_VALUE_U16: u16 = 0;
const DEFAULT_VALUE_U32: u32 = 0;
const ENDIANNESS: SgxSerdeEndian = SgxSerdeEndian::LittleEndian;

/// Provide a wrapper around sgx_quote_t structure
/// typedef uint8_t sgx_epid_group_id_t[4];
/// typedef uint16_t sgx_isv_svn_t;
/// typedef struct _quote_t
/// {
///     uint16_t            version;                /* 0   */
///     uint16_t            sign_type;              /* 2   */
///     sgx_epid_group_id_t epid_group_id;          /* 4   */
///     sgx_isv_svn_t       qe_svn;                 /* 8   */
///     sgx_isv_svn_t       pce_svn;                /* 10  */
///     uint32_t            extended_epid_group_id; /* 12  */
///     sgx_basename_t      basename;               /* 16  */
///     sgx_report_body_t   report_body;            /* 48  */
///     uint32_t            signature_len;          /* 432 */
///     uint8_t             signature[];            /* 436 */
/// } sgx_quote_t;
///
/// See: https://01.org/sites/default/files/documentation/
///     intel_sgx_sdk_developer_reference_for_linux_os_pdf.pdf
#[derive(Serialize, Deserialize)]
pub struct SgxQuote {
    version: u16,
    sign_type: u16,
    epid_group_id: [u8; EPID_GROUP_ID_SIZE],
    qe_svn: u16,
    pce_svn: u16,
    extended_epid_group_id: u32,
    basename: SgxBasename,
    report_body: SgxReportBody,
    // Note that signature is a optional parameter, there are cases
    // where it's not sent. Current version of code does not consider
    // to serialize or deserialize.
    // #[serde(default)]
    // signature_len: Option<u32>,
    // #[serde(default)]
    // signature: Option<Vec<u8>>,
}

impl SgxQuote {
    pub fn basename(&self) -> &SgxBasename {
        &self.basename
    }

    pub fn report_body(&self) -> &SgxReportBody {
        &self.report_body
    }
}

impl SgxStruct for SgxQuote {
    /// Create an instance of SgxMeasurements with default value
    fn default() -> SgxQuote {
        SgxQuote {
            version: DEFAULT_VALUE_U16,
            sign_type: DEFAULT_VALUE_U16,
            epid_group_id: [DEFAULT_VALUE; EPID_GROUP_ID_SIZE],
            qe_svn: DEFAULT_VALUE_U16,
            pce_svn: DEFAULT_VALUE_U16,
            extended_epid_group_id: DEFAULT_VALUE_U32,
            basename: SgxBasename::default(),
            report_body: SgxReportBody::default(),
        }
    }

    /// Serializes a object representing an SGX structure to bytes laid out in its corresponding
    /// C/C++ format.
    fn serialize_to_bytes(&self) -> Result<Vec<u8>, SgxStructError> {
        serialize_to_bytes(&ENDIANNESS, &self)
    }

    /// Parses a byte array and creates the Sgx* object corresponding to the C/C++ struct.
    fn parse_from_bytes(
        &mut self,
        raw_buffer: &[u8],
    ) -> Result<(), SgxStructError> {
        match parse_from_bytes(&ENDIANNESS, &raw_buffer[..FIXED_STRUCT_SIZE]) {
            Ok((
                version,
                sign_type,
                epid_group_id,
                qe_svn,
                pce_svn,
                extended_epid_group_id,
                basename,
                report_body,
            )) => {
                self.version = version;
                self.sign_type = sign_type;
                self.epid_group_id = epid_group_id;
                self.qe_svn = qe_svn;
                self.pce_svn = pce_svn;
                self.extended_epid_group_id = extended_epid_group_id;
                self.basename = basename;
                self.report_body = report_body;
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_from_bytes() {
        let mut sgx_quote = SgxQuote::default();
        let raw_bytes = vec![
            2, 0, 1, 0, 217, 10, 0, 0, 7, 0, 6, 0, 0, 0, 0, 0, 157, 31, 236,
            28, 0, 215, 62, 232, 201, 122, 30, 54, 213, 178, 21, 247, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 7, 255, 255, 255, 2, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0,
            0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 254, 232, 65, 89, 16, 105,
            8, 247, 179, 67, 74, 145, 183, 176, 27, 191, 34, 57, 109, 237, 140,
            104, 45, 70, 54, 202, 6, 4, 242, 229, 180, 63, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 131, 215, 25, 231, 125, 234, 202, 20, 112, 246, 186, 246,
            42, 77, 119, 67, 3, 200, 153, 219, 105, 2, 15, 156, 112, 238, 29,
            252, 8, 199, 206, 158, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 231, 144, 1, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 110, 252, 179, 234, 139,
            7, 160, 133, 198, 185, 19, 90, 154, 172, 86, 108, 10, 27, 119, 179,
            66, 46, 122, 202, 224, 125, 52, 45, 203, 28, 216, 216, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        match sgx_quote.parse_from_bytes(&raw_bytes) {
            Ok(_) => assert!(true),
            Err(err) => {
                println!("{}", format!("{:?}", err));
                assert!(false);
            }
        }
    }

    #[test]
    fn test_serialize_to_bytes() {
        let sgx_quote = SgxQuote::default();
        let bytes = sgx_quote.serialize_to_bytes();
        match bytes {
            Ok(result) => {
                let mut sgx_second = SgxQuote::default();
                match sgx_second.parse_from_bytes(&result) {
                    Err(err) => {
                        println!("{}", format!("{:?}", err));
                        assert!(false);
                    }
                    Ok(_) => assert!(true),
                };
            }
            Err(err) => {
                assert!(false);
            }
        }
    }
}
