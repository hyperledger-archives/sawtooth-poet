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

#[macro_use]
extern crate clap;
extern crate crypto;
#[macro_use]
extern crate log;
extern crate base64;
extern crate log4rs;
extern crate protobuf;
extern crate sawtooth_sdk;
#[macro_use]
extern crate serde;
extern crate bincode;
extern crate serde_json;
#[macro_use]
extern crate serde_big_array;
extern crate hex;
extern crate openssl;

use crate::validator_registry_tp_handler::ValidatorRegistryTransactionHandler;
use log::LogLevelFilter;
use log4rs::{
    append::console::ConsoleAppender,
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};
use sawtooth_sdk::processor::TransactionProcessor;
use std::process;

mod protos;
mod sgx_structs;
mod validator_registry_tp_handler;
mod validator_registry_tp_verifier;

fn main() {
    let matches = clap_app!(validator_registry_tp =>
        (version: crate_version!())
        (about: "Validator Registry Transaction Processor")
        (@arg connect: -C --connect +takes_value
         "connection endpoint for validator")
        (@arg verbose: -v --verbose +multiple
         "increase output verbosity"))
    .get_matches();

    let endpoint = matches
        .value_of("connect")
        .unwrap_or("tcp://localhost:4004");

    let console_log_level;
    match matches.occurrences_of("verbose") {
        0 => console_log_level = LogLevelFilter::Warn,
        1 => console_log_level = LogLevelFilter::Info,
        2 => console_log_level = LogLevelFilter::Debug,
        3 | _ => console_log_level = LogLevelFilter::Trace,
    }

    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{h({l:5.5})} | {({M}:{L}):20.20} | {m}{n}",
        )))
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(console_log_level))
        .unwrap_or_else(|err| {
            error!("{}", err);
            process::exit(1);
        });

    log4rs::init_config(config).unwrap_or_else(|err| {
        error!("{}", err);
        process::exit(1);
    });

    let handler = ValidatorRegistryTransactionHandler::new();
    let mut processor = TransactionProcessor::new(endpoint);

    info!("Console logging level: {}", console_log_level);

    processor.add_handler(&handler);
    processor.start();
}
