# Cabal Replacement Game Services

Reverse-engineered replacement for the following Cabal Online Episode 8 server-side services:
 - RockAndRoll (as `crypto`) - fully functional
 - EventMgr (as `event`) - functional, but doesn't provide any events
 - GlobalMgrSvr (as `gms`) - functional, so far only tested with a single WorldSvr
 - LoginMgr - WIP

This project is aiming to replace most dummy Cabal services with one, single executable. There's no extra functionality added, currently this is aiming only at simplification and demystification.

# Building & Running

```bash
$ cargo build
$ RUST_LOG=info cargo run -- --resources-dir server/resources/ -s event -s crypto -s gms
```

The above has no dependencies, can be run at any time, and replaces EventMgr, RockAndRoll, and GlobalMgrSvr within any Cabal Online Episode 8 server instance. The original RockAndRoll, EventMgr, and GlobalMgrSvr can be removed - they won't be used at all.
