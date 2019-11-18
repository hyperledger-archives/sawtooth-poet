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
    sgx_attributes::SgxAttributes,
    sgx_cpu_svn::SgxCpuSvn,
    sgx_measurement::SgxMeasurement,
    sgx_report_data::SgxReportData,
    sgx_struct_error::SgxStructError,
    sgx_struct_serde::{parse_from_bytes, serialize_to_bytes, SgxSerdeEndian},
    SgxStruct,
};

/// const STRUCT_SIZE: usize = 384;
const RESERVED1: usize = 28;
const RESERVED2: usize = 32;
const RESERVED3: usize = 96;
const RESERVED4: usize = 60;
const DEFAULT_VALUE: u8 = 0;
const ENDIANNESS: SgxSerdeEndian = SgxSerdeEndian::LittleEndian;

big_array! { BigArray;
    RESERVED3, RESERVED4,
}

/// Provide a wrapper around sgx_report_body_t structure
///
/// typedef uint32_t sgx_misc_select_t;
/// typedef uint16_t sgx_prod_id_t;
/// typedef uint16_t sgx_isv_svn_t;
///
/// typedef struct _report_body_t
/// {
///     sgx_cpu_svn_t           cpu_svn;        /* 0   */
///     sgx_misc_select_t       misc_select;    /* 16  */
///     uint8_t                 reserved1[28];  /* 20  */
///     sgx_attributes_t        attributes;     /* 48  */
///     sgx_measurement_t       mr_enclave;     /* 64  */
///     uint8_t                 reserved2[32];  /* 96  */
///     sgx_measurement_t       mr_signer;      /* 128 */
///     uint8_t                 reserved3[96];  /* 160 */
///     sgx_prod_id_t           isv_prod_id;    /* 256 */
///     sgx_isv_svn_t           isv_svn;        /* 258 */
///     uint8_t                 reserved4[60];  /* 260 */
///     sgx_report_data_t       report_data;    /* 320 */
/// } sgx_report_body_t;
///
/// See: https://01.org/sites/default/files/documentation/
///     intel_sgx_sdk_developer_reference_for_linux_os_pdf.pdf
#[derive(Serialize, Deserialize)]
pub struct SgxReportBody {
    cpu_svn: SgxCpuSvn,
    misc_select: u32,
    reserved1: [u8; RESERVED1],
    attributes: SgxAttributes,
    mr_enclave: SgxMeasurement,
    reserved2: [u8; RESERVED2],
    mr_signer: SgxMeasurement,
    #[serde(with = "BigArray")]
    reserved3: [u8; RESERVED3],
    isv_prod_id: u16,
    isv_svn: u16,
    #[serde(with = "BigArray")]
    reserved4: [u8; RESERVED4],
    report_data: SgxReportData,
}

impl SgxReportBody {
    pub fn mr_enclave(&self) -> &SgxMeasurement {
        &self.mr_enclave
    }

    pub fn report_data(&self) -> &SgxReportData {
        &self.report_data
    }
}

impl SgxStruct for SgxReportBody {
    /// Create an instance of SgxReportBody with default value
    fn default() -> SgxReportBody {
        SgxReportBody {
            cpu_svn: SgxCpuSvn::default(),
            misc_select: 0,
            reserved1: [DEFAULT_VALUE; RESERVED1],
            attributes: SgxAttributes::default(),
            mr_enclave: SgxMeasurement::default(),
            reserved2: [DEFAULT_VALUE; RESERVED2],
            mr_signer: SgxMeasurement::default(),
            reserved3: [DEFAULT_VALUE; RESERVED3],
            isv_prod_id: 0,
            isv_svn: 0,
            reserved4: [DEFAULT_VALUE; RESERVED4],
            report_data: SgxReportData::default(),
        }
    }

    /// Serializes a object representing an SGX structure to bytes laid out in its corresponding
    /// C/C++ format.
    ///
    /// NOTE: All integer struct fields are serialized to little endian format
    fn serialize_to_bytes(&self) -> Result<Vec<u8>, SgxStructError> {
        serialize_to_bytes(&ENDIANNESS, &self)
    }

    /// Parses a byte array and creates the Sgx* object corresponding to the C/C++ struct.
    fn parse_from_bytes(
        &mut self,
        raw_buffer: &[u8],
    ) -> Result<(), SgxStructError> {
        let sgx_report_body: SgxReportBody =
            match parse_from_bytes(&ENDIANNESS, raw_buffer) {
                Ok(result) => result,
                Err(err) => return Err(err),
            };
        self.cpu_svn = sgx_report_body.cpu_svn;
        self.misc_select = sgx_report_body.misc_select;
        self.reserved1 = sgx_report_body.reserved1;
        self.attributes = sgx_report_body.attributes;
        self.mr_enclave = sgx_report_body.mr_enclave;
        self.reserved2 = sgx_report_body.reserved2;
        self.mr_signer = sgx_report_body.mr_signer;
        self.reserved3 = sgx_report_body.reserved3;
        self.isv_prod_id = sgx_report_body.isv_prod_id;
        self.isv_svn = sgx_report_body.isv_svn;
        self.reserved4 = sgx_report_body.reserved4;
        self.report_data = sgx_report_body.report_data;
        Ok(())
    }
}
