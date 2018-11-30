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

extern crate bincode;
#[macro_use]
extern crate clap;
extern crate crypto;
extern crate hyper;
extern crate ias_client;
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate log4rs;
extern crate num;
extern crate openssl;
extern crate protobuf;
extern crate rand;
extern crate sawtooth_sdk;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate sgxffi;
extern crate toml;
extern crate validator_registry_tp;
extern crate zmq;

use engine::Poet2Engine;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use log::LevelFilter;
use poet2_util::read_file_as_string;
use poet_config::PoetConfig;
use sawtooth_sdk::consensus::zmq_driver::ZmqDriver;
use std::process;
use toml as toml_converter;

pub mod engine;
pub mod service;
pub mod enclave_sgx;
pub mod database;
pub mod poet2_util;
pub mod settings_view;
mod registration;
mod poet_config;

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
        (about: "PoET Consensus Engine")
        (@arg config: --config +takes_value
        "PoET toml config file")
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

    // read configuration file, i.e. TOML confiuration file
    let config_file = matches.value_of("config")
        .expect("Config file is not input, use -h for information");

    let file_contents = read_file_as_string(config_file);
    info!("Read file contents: {}", file_contents);
    let config: PoetConfig = toml_converter::from_str(file_contents.as_str())
        .expect("Error reading toml config file");

    let (driver, _stop_handle) = ZmqDriver::new();
    info!("Starting the ZMQ Driver...");

    driver.start(&endpoint, Poet2Engine::new(config)).unwrap_or_else(|_err| {
        process::exit(1);
    });
}
