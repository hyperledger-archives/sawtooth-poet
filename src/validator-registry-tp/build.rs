/*
 * Copyright 2018 Intel Corporation
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

use std::{env, fs, path::PathBuf};

fn main() {
    println!("Check if building for SGX hardware mode");
    let sgx_hw_mode = match env::var("SGX_HW_MODE") {
        Ok(hardware_mode) => {
            if hardware_mode == "TRUE" {
                true
            } else {
                false
            }
        }
        Err(_) => false,
    };

    // Generate verifier module based on sgx_hw_mode information.
    let mut manifest_path =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("Cargo manifest directory not set"));
    manifest_path.push("src");
    let mut source = manifest_path.clone();
    let mut destination = manifest_path;
    destination.push("validator_registry_tp_verifier.rs");
    if sgx_hw_mode {
        println!("Validator registry TP will compile to work in SGX hardware mode");
        source.push("sgx");
    } else {
        println!("Validator registry TP will compile to work in simulator mode");
        source.push("simulator");
    }
    source.push("validator_registry_tp_verifier.rs");
    println!(
        "Copying from {:?} to {:?}",
        source.clone(),
        destination.clone()
    );
    fs::copy(source, destination)
        .expect("Build will fail, because copy operation not permitted in the path!");
}
