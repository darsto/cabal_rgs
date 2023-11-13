// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use clap::Parser;

#[derive(Parser, Debug, Default)]
#[clap(name = "cabal-mgr", version)]
pub struct Args {
    #[clap(flatten)]
    event_mgr_args: crate::event_mgr::Args,
}
