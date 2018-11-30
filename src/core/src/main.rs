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
#[macro_use]
extern crate clap;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate log4rs;
extern crate num;
extern crate protobuf;
extern crate rand;
extern crate sawtooth_sdk;
extern crate zmq;
extern crate crypto;
extern crate bincode;
extern crate sgxffi;

pub mod engine;
pub mod service;
pub mod enclave_sgx;
pub mod database;
pub mod poet2_util;
pub mod settings_view;

use engine::Poet2Engine;
use sawtooth_sdk::consensus::zmq_driver::ZmqDriver;

use std::process;
use log::LevelFilter;
use log4rs::append::file::FileAppender;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;

/*
 *
 * This is the main() method.
 *
 * This is where we parse the command-line args and 
 * setup important parameters like:
 * - endpoint url of validator
 * - verbosity of logging
 * - initiate the zmq driver connection at the "endpoint"
 * - start the poet2 engine/logic code
 *
 * @params None
 *
 */
fn main() {
    let matches = clap_app!(sawtooth_poet =>
        (version: crate_version!())
        (about: "PoET 2 Consensus Engine")
        (@arg connect: -C --connect +takes_value
         "connection endpoint url for validator")
        (@arg verbose: -v --verbose +multiple
         "increase output verbosity"))
        .get_matches();

    let endpoint = matches
        .value_of("connect")
        .unwrap_or("tcp://localhost:5050");

    let log_level;
    match matches.occurrences_of("verbose") {
        0 => log_level = LevelFilter::Warn,
        1 => log_level = LevelFilter::Info,
        2 => log_level = LevelFilter::Debug,
        3 | _ => log_level = LevelFilter::Trace,
    }

   let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d:22.22} {h({l:5.5})} | {({M}:{L}):30.30} | {m}{n}",
        )))
        .build();

    let fileout = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d:22.22} {h({l:5.5})} | {({M}:{L}):30.30} | {m}{n}",
        )))
        .build("log/debug.log")
        .expect("Could not build file appender");

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .appender(Appender::builder().build("fileout", Box::new(fileout)))
        .build(Root::builder().appender("stdout").appender("fileout").build(log_level))
        .unwrap_or_else(|err| {
            error!("{}", err);
            process::exit(1);
        });

    log4rs::init_config(config).unwrap_or_else(|err| {
        error!("{}", err);
        process::exit(1);
    });

    let (driver, _stop_handle) = ZmqDriver::new();
    info!("Starting the ZMQ Driver...");

    driver.start(&endpoint, Poet2Engine::new()).unwrap_or_else(|_err| {
        process::exit(1);
    });
}
