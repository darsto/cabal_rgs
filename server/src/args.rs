// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(ValueEnum, Debug, Clone, PartialEq)]
#[clap(rename_all = "kebab_case")]
pub enum Service {
    CryptoMgr,
    EventMgr,
}

#[derive(Parser, Debug, Default)]
#[clap(name = "cabal-mgr", version)]
pub struct Config {
    #[clap(short = 's', long = "service", value_delimiter = ',', num_args = 1..)]
    pub services: Vec<Service>,

    #[clap(flatten)]
    pub event_mgr_args: crate::event_mgr::Args,

    #[clap(default_value = ".")]
    #[arg(short = 'r', long)]
    pub resources_dir: PathBuf,
}
