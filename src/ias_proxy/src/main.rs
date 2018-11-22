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

extern crate clap;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate log4rs;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate toml;

use clap::{App,
           Arg};
use ias_proxy_config::IasProxyConfig;
use log4rs::{append::{console::ConsoleAppender,
                      file::FileAppender},
             config::{Appender,
                      Config,
                      Root},
             encode::pattern::PatternEncoder};
use log::LogLevelFilter;
use std::process;
use utils::read_file_as_string;

mod ias_proxy_server;
mod lru_cache;
mod ias_proxy_config;
mod utils;

const DEFAULT_CONFIG_FILE: &str = "tests/packaging/ias_proxy.toml";
const LOG_FILE_PATH: &str = "/var/log/sawtooth-poet/ias-proxy.log";

/// Parse arguments and start the IAS proxy server, note that for IAS proxy to start successfully
/// config file input is must. If it's not input then a default file is read.
fn main() {
    let matches = App::new("IAS Proxy Server")
        .version("1.0.0")
        .author("Intel Corporation")
        .about("IAS proxy server")
        .arg(Arg::with_name("config")
            .short("c")
            .long("config")
            .value_name("config")
            .takes_value(true)
            .help("Config file"))
        .arg(Arg::with_name("log-level")
            .long("log-level")
            .value_name("log-level")
            .takes_value(true)
            .help("Logging level"))
        .arg(Arg::with_name("log-file")
            .long("log-file")
            .value_name("log-file")
            .takes_value(true)
            .help("Log file"))
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .value_name("verbose")
            .multiple(true)
            .help("Print debug information"))
        .get_matches();

    let log_level;
    match matches.occurrences_of("verbose") {
        0 => log_level = LogLevelFilter::Warn,
        1 => log_level = LogLevelFilter::Info,
        2 => log_level = LogLevelFilter::Debug,
        3 | _ => log_level = LogLevelFilter::Trace,
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
        .build(LOG_FILE_PATH)
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

    // read configuration file, i.e. toml configuration file
    let config_file = match matches.value_of("config") {
        Some(config_present) => config_present,
        None => {
            info!("Config file is not input, using default configuration, use -h for help");
            DEFAULT_CONFIG_FILE
        }
    };
    let file_contents = read_file_as_string(config_file);
    let config: IasProxyConfig = match toml::from_str(file_contents.as_str()) {
        Ok(config_read) => config_read,
        Err(err) => panic!("Error converting config file: {}", err),
    };

    // Get a proxy server instance and run it
    let proxy_server = ias_proxy_server::get_proxy_server(config);
    proxy_server.run();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_sample_file() {
        let config_file = "src/tests/packaging/ias_proxy.toml";
        let file_contents = read_file_as_string(config_file);
        let config: IasProxyConfig = match toml::from_str(file_contents.as_str()) {
            Ok(config_read) => config_read,
            Err(err) => panic!("Error converting config file: {}", err),
        };
        assert_ne!(config.get_proxy_ip().len(), 0);
        assert!(file_contents.contains(&config.get_proxy_ip()));
        assert_ne!(config.get_proxy_port().len(), 0);
        assert!(file_contents.contains(&config.get_proxy_port()));
        assert_ne!(config.get_ias_url().len(), 0);
        assert!(file_contents.contains(&config.get_ias_url()));
        assert_ne!(config.get_spid_cert_file().len(), 0);
        assert!(file_contents.contains(&config.get_spid_cert_file()));
    }
}
