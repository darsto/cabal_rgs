# Cabal Replacement Game Services

Reverse-engineered replacement for the following Cabal Online Episode 8 server-side services:
 - RockAndRoll (as `crypto`) - fully functional
 - EventMgr (as `event`) - functional, but doesn't provide any events
 - GlobalMgrSvr (as `gms`) - functional, so far only tested with a single WorldSvr
 - LoginSvr - (as `login`) - fully functional

This project is aiming to replace most dummy Cabal services with one, single executable. There's no extra functionality added, currently this is aiming only at simplification and demystification.

# Building & Running

```bash
$ cargo build
$ RUST_LOG=info cargo run -- --resources-dir server/resources/ -s event -s crypto -s gms -s login
```

The above has no dependencies, can be run at any time, and replaces EventMgr, RockAndRoll, GlobalMgrSvr, and LoginSvr within any Cabal Online Episode 8 server instance. The original RockAndRoll, EventMgr, GlobalMgrSvr, and LoginSvr can be removed - they won't be used at all.
