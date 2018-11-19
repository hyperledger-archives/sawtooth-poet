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

pub mod ffi;

#[cfg(test)]
mod tests {
    use super::*;
    use std::str;
    use std::os::raw::c_char;
    use ffi::r_sgx_enclave_id_t;
    use ffi::r_sgx_signup_info_t;       
    use ffi::r_sgx_wait_certificate_t;
    use ffi::r_sgx_epid_group_t;
 
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    //#[test]
    fn init_free_enclave_test() {
        let mut eid:r_sgx_enclave_id_t = r_sgx_enclave_id_t {handle : 0,
                                                mr_enclave:0 as *mut c_char,
                                                basename:0 as *mut c_char};

        //spid should be a valid UTF-8 string of length 32. create all AAAAA's
        let spid_vec = vec![0x41; 32]; 
        let spid_str = str::from_utf8(&spid_vec).unwrap();
        let mut lib_path = std::env::current_dir().unwrap();
        lib_path.push("../../build/bin/libpoet_enclave.signed.so");
        let bin_path = &lib_path.into_os_string().into_string().unwrap();

        let ret = ffi::init_enclave(&mut eid, bin_path, spid_str)
				    .expect("Failed to initialize enclave");
        assert_eq!(ret, "Success");
        
        let ret = ffi::free_enclave(&mut eid).expect("Failed to free enclave");
        assert_eq!(ret, "Success");
    }
        
    
    #[test]
    fn create_wait_certificate_test(){
        let mut eid:r_sgx_enclave_id_t = r_sgx_enclave_id_t {handle : 0,
                                                mr_enclave:0 as *mut c_char,
                                                basename:0 as *mut c_char};

        //spid should be a valid UTF-8 string of length 32. create all AAAAA's
        let spid_vec = vec![0x41; 32];
        let spid_str = str::from_utf8(&spid_vec).unwrap();
        let mut lib_path = std::env::current_dir().unwrap();
        lib_path.push("../../build/bin/libpoet_enclave.signed.so");
        let bin_path = &lib_path.into_os_string().into_string().unwrap();

        let ret = ffi::init_enclave(&mut eid, bin_path, spid_str)
                                    .expect("Failed to initialize enclave");
        assert_eq!(ret, "Success");
        
        let mut epid_info:r_sgx_epid_group_t = r_sgx_epid_group_t {
                                                    epid: 0 as *mut c_char};
        let ret = ffi::get_epid_group(&mut eid, &mut epid_info)
                            .expect("Failed to get EPID group");

        assert_eq!(ret, "Success");

        //check if SGX is running in simulator mode
        let mut sgx_simulator: bool = false;
        let ret = ffi::is_sgx_simulator(&mut eid, &mut sgx_simulator)
                                    .expect("Failed to check SGX simulator");
        assert_eq!(ret, "Success");

        println!("is_sgx_simulator ? {:?}", sgx_simulator);

        //Create signup info
        let opk_hash_vec = "ABCD" ;
        let mut signup_info:r_sgx_signup_info_t
                                        = r_sgx_signup_info_t {handle:0,
                                            poet_public_key : 0 as *mut c_char,
                                            poet_public_key_len : 0,
                                            enclave_quote : 0 as *mut c_char };

        let ret = ffi::create_signup_info(&mut eid, &opk_hash_vec,
                                          &mut signup_info)
                                    .expect("Failed to create signup info");
        assert_eq!(ret, "Success");

        let ppk_str: String = ffi::create_string_from_char_ptr(
                                signup_info.poet_public_key as *mut c_char);
        println!("Poet Public Key : {}", ppk_str);

        //Create wait certificate
        let mut duration: u64 = 0x0102030405060708;
        let prev_cert = "";
        let prev_block_id = "abc";
        let prev_wait_cert_sig = "";
        let validator_id = "123";
        let block_summary = "this is first block";
        let wait_time = 10_u64;
        let mut verify_wait_cert_status: bool = false;

        let mut wait_cert_info:r_sgx_wait_certificate_t
                         = r_sgx_wait_certificate_t{ handle: 0,
                                        ser_wait_cert: 0 as *mut c_char,
                                        ser_wait_cert_sign: 0 as *mut c_char
                                        };

        // initialize wait certificate - to get duration from enclave
        let ret = ffi::initialize_wait_cert(&mut eid, &mut duration,
                                            &prev_cert, &prev_wait_cert_sig,
                                            &validator_id, &ppk_str.as_str())
                            .expect("Failed to initialize wait certificate");
        assert_eq!(ret, "Success");

        println!("duration inside rust layer 0x{:016x?}", duration);

        // finalize wait certificate - to get wait certificate
        let ret = ffi::finalize_wait_cert(&mut eid, &mut wait_cert_info,
                                          &prev_cert, &prev_block_id,
                                          &prev_wait_cert_sig,
                                          &block_summary, &wait_time)
                                .expect("Failed to finalize wait certificate");
        assert_eq!(ret, "Success");

        let wait_cert = ffi::create_string_from_char_ptr(
                                wait_cert_info.ser_wait_cert as *mut c_char);
        let wait_cert_sign = ffi::create_string_from_char_ptr(
                             wait_cert_info.ser_wait_cert_sign as *mut c_char);

        println!("wait_cert = {:?}", wait_cert);
        //verify wait certificate
        let ret = ffi::verify_wait_certificate(&mut eid, &wait_cert.as_str(),
                                               &wait_cert_sign.as_str(),
                                               &ppk_str.as_str(),
                                               &mut verify_wait_cert_status)
                                .expect("Failed to verify wait certificate");
        assert_eq!(ret, "Success");
        println!("Is verification of wait certificate Passed: {}",
                                                    verify_wait_cert_status);

        let ret = ffi::release_wait_certificate(&mut eid,
                                                &mut wait_cert_info)
                                .expect("Failed to release wait certificate");
        assert_eq!(ret, "Success");
      
        let ret = ffi::release_signup_info(&mut eid, &mut signup_info)
                                    .expect("Failed to release signup info");
        assert_eq!(ret, "Success");

        let ret = ffi::free_enclave(&mut eid).expect("Failed to free enclave");
        assert_eq!(ret, "Success");
    }
}
