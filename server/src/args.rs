// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug, Default)]
#[clap(name = "cabal-mgr", version)]
pub struct Config {
    #[clap(flatten)]
    pub event_mgr_args: crate::event_mgr::Args,

    #[clap(default_value = ".")]
    #[arg(short = 'r', long)]
    pub resources_dir: PathBuf,
}
