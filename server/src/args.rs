// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use std::{ffi::OsString, path::PathBuf, sync::OnceLock};

use clap::{Parser, Subcommand};

/// Cabal Online Replacement Services
///
/// You can run this as a single specific --service, or any combination of
/// them with multiple --service arguments. If a service expects additional
/// options, you can specify them immediately after --service.
#[derive(Parser, Debug)]
#[clap(bin_name = format!("{} --service", bin_name()))]
#[clap(version, about, long_about, verbatim_doc_comment)]
#[clap(flatten_help = true)]
#[clap(disable_help_subcommand = true)]
#[clap(override_usage = format!("{} [OPTIONS] -s|--service <SERVICE1> -s|--service <SERVICE2>", bin_name()))]
struct Args {
    #[clap(subcommand)]
    service: Service,
    #[clap(flatten)]
    common: CommonConfig,
}

#[derive(Subcommand, Debug)]
#[clap(rename_all = "kebab_case")]
pub enum Service {
    #[cfg(feature = "crypto")]
    Crypto(crate::crypto::CryptoArgs),
    #[cfg(feature = "event")]
    Event(crate::event::EventArgs),
    #[cfg(feature = "proxy")]
    Proxy(crate::proxy::ProxyArgs),
    #[cfg(feature = "gms")]
    Gms(crate::gms::GmsArgs),
    #[cfg(feature = "login")]
    Login(crate::login::LoginArgs),
    #[cfg(feature = "party")]
    Party(crate::party::PartyArgs),
}

/// Common (non-service-specific) configuration
#[derive(Parser, Debug, Default)]
pub struct CommonConfig {
    #[arg(default_value = ".")]
    #[arg(short = 'r', long)]
    pub resources_dir: PathBuf,
}

/// The final config structure used at runtime
#[derive(Debug)]
pub struct Config {
    pub services: Vec<Service>,
    pub common: CommonConfig,
}

impl Service {
    fn parse_from_args<I, T>(args: I) -> Self
    where
        I: Iterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let args = std::iter::once(bin_name().into()).chain(args.map(Into::into));

        Args::parse_from(args).service
    }
}

fn bin_name() -> &'static str {
    static BIN_NAME: OnceLock<PathBuf> = OnceLock::new();
    BIN_NAME
        .get_or_init(|| std::env::current_exe().unwrap())
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
}

pub fn parse() -> Config {
    let args: Vec<String> = std::env::args().collect();
    parse_from(&args)
}

/// Clap currently doesn't support running multiple subcommands:
/// https://github.com/clap-rs/clap/issues/2222
/// We work around it by parsing the args string manually, and feeding
/// different parts back into the original Parser potentially multiple
/// times.
pub fn parse_from(args: &[String]) -> Config {
    let mut services: Vec<Service> = Vec::new();
    let mut common_cfg: Option<CommonConfig> = None;

    let mut cur_service_start_idx: Option<usize> = None;
    for (idx, arg) in args.iter().enumerate() {
        if arg == "-s" || arg == "--service" {
            if let Some(cur_service_start_idx) = cur_service_start_idx {
                // end collecting the args of the previous service and try to parse them
                let service_args = &args[cur_service_start_idx..idx];
                let service_cfg = Service::parse_from_args(service_args.iter());
                services.push(service_cfg);
            } else {
                // this is the first -s we see, so parse the previous args
                // as common, generic args
                let cfg = CommonConfig::parse_from(args.iter().take(idx));
                common_cfg = Some(cfg);
            }

            cur_service_start_idx = Some(idx + 1);
        }
    }

    if let Some(cur_service_start_idx) = cur_service_start_idx {
        let service_args = args.iter().skip(cur_service_start_idx);
        let service_cfg = Service::parse_from_args(service_args);
        services.push(service_cfg);
    } else {
        // there were no services specified, so we should fail, but the user
        // might have requested either --version or --help
        for arg in args {
            match arg.as_str() {
                "-V" | "--version" | "-h" | "--help" => {
                    Args::parse_from(["bin", arg].iter());
                }
                _ => {}
            }
        }
        Args::parse_from(["bin"].iter());
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
