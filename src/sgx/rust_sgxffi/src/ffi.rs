/*
 Copyright 2018 Intel Corporation

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

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bindings.rs"));

use std::str;
use std::ffi::CStr;
use std::ffi::CString;
use std::mem::transmute;
use ffi::r_error_code_t::R_SUCCESS;
use ffi::r_error_code_t::R_FAILURE;

pub fn init_enclave(eid: &mut r_sgx_enclave_id_t, signed_enclave: &str,
                    spid: &str) -> Result<String, String> {
    unsafe {
        let eid_ptr = eid as *mut r_sgx_enclave_id_t;
        let enclave_cstring = CString::new(signed_enclave).unwrap();
        let spid_cstring = CString::new(spid).unwrap();
        let enclave_init_status = r_initialize_enclave(eid_ptr,
                                                    enclave_cstring.as_ptr(),
                                                    spid_cstring.as_ptr());

        match enclave_init_status {
            R_SUCCESS => Ok("Success".to_string()),
            R_FAILURE => Err("Enclave initialization failed".to_string()),
        }
    }
}

pub fn free_enclave(eid: &mut r_sgx_enclave_id_t) -> Result<String, String> {
    unsafe {
        let eid_ptr = eid as *mut r_sgx_enclave_id_t;                
        let enclave_free_status = r_free_enclave(eid_ptr);

        match enclave_free_status {
            R_SUCCESS => Ok("Success".to_string()),
            R_FAILURE => Err("Enclave free failed".to_string()),
        }
    }    
}

pub fn get_epid_group(eid: &mut r_sgx_enclave_id_t,
                      epid_group: &mut r_sgx_epid_group_t)
                      -> Result<String, String>{
    unsafe {
        let eid_ptr = eid as *mut r_sgx_enclave_id_t;
        let epid_group_ptr = epid_group as *mut r_sgx_epid_group_t;
        let epid_status = r_get_epid_group(eid_ptr, epid_group_ptr);
        match epid_status {
             R_SUCCESS => Ok("Success".to_string()),
             R_FAILURE => Err("Get EPID group failed".to_string()),
        }
    }
}

pub fn is_sgx_simulator(eid: &mut r_sgx_enclave_id_t, sgx_simulator: &mut bool)
                        -> Result<String, String> {
    unsafe {
        let eid_ptr = eid as *mut r_sgx_enclave_id_t;
        let sgx_simulator_ptr = sgx_simulator as *mut bool;
        let status = r_is_sgx_simulator(eid_ptr, sgx_simulator_ptr);

        match status {
             R_SUCCESS => Ok("Success".to_string()),
             R_FAILURE => Err("SGX simulator check failed".to_string()),
        }
    }
}

pub fn set_sig_revocation_list(eid: &mut r_sgx_enclave_id_t, 
                        sig_rev_list: &str) -> Result<String, String> {
    unsafe {
        let eid_ptr = eid as *mut r_sgx_enclave_id_t;
        let sig_rev_list_cstring =  CString::new(sig_rev_list).unwrap();
        let sig_revocation_status = r_set_signature_revocation_list(eid_ptr, 
                                            sig_rev_list_cstring.as_ptr());
        match sig_revocation_status {
            R_SUCCESS => Ok("Success".to_string()),
            R_FAILURE => Err("Set sig revocation list failed".to_string()),
        }
    }
}

pub fn create_signup_info(eid: &mut r_sgx_enclave_id_t, opk_hash: &str,
                          signup_info: &mut r_sgx_signup_info_t)
                          -> Result<String, String> {
    unsafe {
        let eid_ptr = eid as *mut r_sgx_enclave_id_t;
        let signup_info_ptr = signup_info as *mut r_sgx_signup_info_t;
        let opk_hash_cstring = CString::new(opk_hash).unwrap();
        let signup_status = r_create_signup_info(eid_ptr, 
                                            opk_hash_cstring.as_ptr(), 
                                            signup_info_ptr);

        match signup_status {
            R_SUCCESS => Ok("Success".to_string()),
            R_FAILURE => Err("Create Signup info failed".to_string()),
        }
    } 
}

pub fn initialize_wait_cert(eid: &mut r_sgx_enclave_id_t, duration: &mut u64,
                            prev_wait_cert: &str, prev_wait_cert_sig: &str,
                            validator_id: &str,
                            poet_pub_key: &str) -> Result<String, String> {
    unsafe {
        let eid_ptr = eid as *mut r_sgx_enclave_id_t;
        
        let mut duration_arr: [u8; 8] =  [0;8];

        let duration_ptr = duration_arr.as_mut_ptr();
        let prev_wait_cert_cstring = CString::new(prev_wait_cert).unwrap();
        let prev_wait_cert_sig_cstring = CString::new(prev_wait_cert_sig)
                                                                .unwrap();
        let validator_id_ctring = CString::new(validator_id).unwrap();
        let poet_pub_key_cstring = CString::new(poet_pub_key).unwrap();

        let wait_cert_init_status = r_initialize_wait_certificate(eid_ptr, 
                                        duration_ptr, 
                                        prev_wait_cert_cstring.as_ptr(),
                                        prev_wait_cert_sig_cstring.as_ptr(),
                                        validator_id_ctring.as_ptr(),
                                        poet_pub_key_cstring.as_ptr());  

        //convert u8 array to u64 duration
        if wait_cert_init_status == r_error_code_t::R_SUCCESS {
            *duration = transmute::<[u8; 8], u64>(duration_arr).to_le();
        }

        match wait_cert_init_status {
            R_SUCCESS => Ok("Success".to_string()),
            R_FAILURE => Err("Initialize certificate failed".to_string()),
        }
    }
     
}

pub fn finalize_wait_cert(eid: &mut r_sgx_enclave_id_t, 
                          wait_cert_info: &mut r_sgx_wait_certificate_t,
                          prev_wait_cert: &str,
                          prev_block_id: &str, prev_wait_cert_sig: &str,
                          block_summary: &str, 
                          wait_time: &u64) -> Result<String, String> {
    unsafe {
        let eid_ptr = eid as *mut r_sgx_enclave_id_t;
        let wait_cert_ptr = wait_cert_info  as *mut r_sgx_wait_certificate_t;
        let prev_wait_cert_cstring = CString::new(prev_wait_cert).unwrap();
        let prev_block_id_cstring = CString::new(prev_block_id).unwrap();
        let prev_wait_cert_sig_cstring = CString::new(prev_wait_cert_sig)
                                                                .unwrap();
        let block_summary_cstring = CString::new(block_summary).unwrap();

        let wait_cert_final_status = r_finalize_wait_certificate(eid_ptr, 
                                                wait_cert_ptr, 
                                                prev_wait_cert_cstring.as_ptr(),
                                                prev_block_id_cstring.as_ptr(),
                                                prev_wait_cert_sig_cstring.as_ptr(),
                                                block_summary_cstring.as_ptr(),
                                                *wait_time);
 
        match wait_cert_final_status {
            R_SUCCESS => Ok("Success".to_string()),
            R_FAILURE => Err("Finalize certificate failed".to_string()),
        }
    }
}

pub fn verify_wait_certificate(eid: &mut r_sgx_enclave_id_t,
                               wait_cert: &str,
                               wait_cert_sign: &str,
                               ppk: &str,
                               verify_cert_status: &mut bool)
                               -> Result<String, String> {
    unsafe {
        
        let eid_ptr = eid as *mut r_sgx_enclave_id_t;
        let verify_cert_status_ptr = verify_cert_status as *mut bool;
        let wait_cert_cstring = CString::new(wait_cert).unwrap();

        let wait_cert_sign_cstring = CString::new(wait_cert_sign).unwrap();

        let ppk_cstring = CString::new(ppk).unwrap();

        let status = r_verify_wait_certificate(eid_ptr, ppk_cstring.as_ptr(),
                                               wait_cert_cstring.as_ptr(),
                                               wait_cert_sign_cstring.as_ptr(),
                                               verify_cert_status_ptr);

        match status {
             R_SUCCESS => Ok("Success".to_string()),
             R_FAILURE => Err("Verify wait certificate failed".to_string()),
        }
    }
}

pub fn create_string_from_char_ptr(cchar_ptr : *mut ::std::os::raw::c_char)
                                   -> String {
    let c_str: &CStr = unsafe { CStr::from_ptr(cchar_ptr) };
    let str_slice: &str = c_str.to_str().unwrap();
    let string_buf: String = str_slice.to_owned();

    string_buf
}

pub fn release_signup_info(eid: &mut r_sgx_enclave_id_t, 
                           signup_info: &mut r_sgx_signup_info_t)
                           -> Result<String, String> {
    unsafe {
        let eid_ptr = eid as *mut r_sgx_enclave_id_t;
        let signup_info_ptr = signup_info as *mut r_sgx_signup_info_t;                
        let singup_release_status = r_release_signup_info(eid_ptr, 
                                                    signup_info_ptr);

        match singup_release_status {
            R_SUCCESS => Ok("Success".to_string()),
            R_FAILURE => Err("Release signup info failed".to_string()),
        }
    } 

}

pub fn release_wait_certificate(eid: &mut r_sgx_enclave_id_t, 
                                wait_cert: &mut r_sgx_wait_certificate_t)
                                -> Result<String, String> {
    unsafe {
        let eid_ptr = eid as *mut r_sgx_enclave_id_t;
        let wait_cert_ptr = wait_cert as * mut r_sgx_wait_certificate_t;
        let wait_cert_release_status = r_release_wait_certificate(eid_ptr, 
                                                    wait_cert_ptr);

        match wait_cert_release_status {
            R_SUCCESS => Ok("Success".to_string()),
            R_FAILURE => Err("Release wait certificate failed".to_string()),
        }
    }
}
