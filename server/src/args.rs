// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

// Enum used for --service string parsing and --help pretty printing
#[derive(Subcommand, ValueEnum, Debug, Clone, PartialEq)]
#[clap(rename_all = "kebab_case")]
enum ServiceConfigArg {
    /// RockAndRoll equivalent
    Crypto,
    /// EventMgr equivalent
    Event,
    /// GlobalMgrSvr equivalent
    Gms,
    Proxy,
}

/// A service configuration
#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum Service {
    Crypto(crate::crypto::CryptoArgs),
    Event(crate::event::EventArgs),
    Proxy(crate::proxy::ProxyArgs),
    Gms(crate::gms::GmsArgs),
}

impl Service {
    fn parse_from_args(stype: ServiceConfigArg, args: std::slice::Iter<String>) -> Self {
        let prefix = [format!(
            "{BIN_NAME} -s {}",
            stype.to_possible_value().unwrap().get_name()
        )];
        let args = prefix.iter().chain(args);
        match stype {
            ServiceConfigArg::Crypto => Self::Crypto(crate::crypto::CryptoArgs::parse_from(args)),
            ServiceConfigArg::Event => Self::Event(crate::event::EventArgs::parse_from(args)),
            ServiceConfigArg::Gms => Self::Gms(crate::gms::GmsArgs::parse_from(args)),
            ServiceConfigArg::Proxy => Self::Proxy(crate::proxy::ProxyArgs::parse_from(args)),
        }
    }
}

/// Common (non-service-specific) configuration
#[derive(Parser, Debug, Default)]
pub struct CommonConfig {
    #[clap(default_value = ".")]
    #[arg(short = 'r', long)]
    pub resources_dir: PathBuf,
}

// Clap representation of our argument parsing. This is only used for --help
// and printing some error messages. We want to support running multiple services
// in one app, but clap currently doesn't support that:
// https://github.com/clap-rs/clap/issues/2222
// We work around it by parsing the args string manually, and passing different parts
// to different sub-parsers.

static BIN_NAME: &str = "cabal-mgr";

/// Cabal Online Replacement Services
#[derive(Parser, Debug)]
#[command(display_name = "cabal-mgr", bin_name = "cabal-mgr")]
#[command(version, about, long_about, verbatim_doc_comment)]
#[command(subcommand_value_name = "\x08 \n\
\x20         [-s|--service <SERVICE1> <SERVICE1_OPTIONS>]\n\
\x20         [-s|--service <SERVICE2...>]\x1b")]
#[command(subcommand_help_heading = "Services")]
#[command(disable_help_subcommand = true)]
#[command(after_long_help = "\x1b[1;4mExamples:\x1b[0m\n\
\x20 ./cabal_mgr -s crypto --service event")]
struct Args {
    #[command(subcommand)]
    service: ServiceConfigArg,
    #[clap(flatten)]
    common: CommonConfig,
}

// Parser for --service parsing; nothing else
#[derive(Parser, Debug)]
struct ServiceConfig {
    #[arg(short = 's', long = "service", value_name = "service")]
    inner: ServiceConfigArg,
}

#[derive(Debug)]
pub struct Config {
    pub services: Vec<Service>,
    pub common: CommonConfig,
}

pub fn parse() -> Config {
    let args: Vec<String> = std::env::args().collect();
    parse_from(&args)
}

pub fn parse_from(args: &[String]) -> Config {
    let mut services: Vec<Service> = Vec::new();
    let mut common_cfg: Option<CommonConfig> = None;

    let mut cur_service: Option<(usize, ServiceConfigArg)> = None;
    let mut iter = args.iter().enumerate();
    while let Some((idx, arg)) = iter.next() {
        if arg == "-s" || arg == "--service" {
            if let Some(cur_service) = cur_service {
                // end collecting the args of the previous service and try to parse them
                let service_args = &args[cur_service.0..idx];
                let service_cfg = Service::parse_from_args(cur_service.1, service_args.iter());
                services.push(service_cfg);
            } else {
                // this is the first -s we see, so parse the previous args
                // as common, generic args
                let full_cfg =
                    Args::parse_from(args.iter().take(idx).chain(["crypto".into()].iter()));
                common_cfg = Some(full_cfg.common);
            }

            let mut service_config_args = vec![&args[0], arg];
            if let Some((_, service_name)) = iter.next() {
                service_config_args.push(service_name);
            }

            // delegating all input parsing to clap gives us consistent error
            // handling and consistent error messages
            let service = ServiceConfig::parse_from(service_config_args);
            cur_service = Some((idx + 2, service.inner));
        }
    }

    if let Some(cur_service) = cur_service {
        let service_args = &args[cur_service.0..args.len()];
        let service_cfg = Service::parse_from_args(cur_service.1, service_args.iter());
        services.push(service_cfg);
    } else {
        // there were no services specified, so we should fail, but the user
        // might have requested either --version or --help
        for arg in args {
            match arg.as_str() {
                "-V" | "--version" | "-h" | "--help" => {
                    Args::parse_from([BIN_NAME.to_owned(), arg.clone()].iter());
                }
                _ => {}
            }
        }
        Args::parse_from([BIN_NAME.to_owned()].iter());
        unreachable!();
    }

    Config {
        services,
        common: common_cfg.unwrap_or_default(),
    }
}

pub fn parse_from_str(str: &str) -> Config {
    let args = str.split_ascii_whitespace();
    let iter = std::env::args().take(1).chain(args.map(|s| s.into()));
    parse_from(&iter.collect::<Vec<String>>())
}
