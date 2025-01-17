# Cabal Replacement Server Services

This is aiming to rewrite all Cabal Online Episode 8 server-side services besides WorldSvr and DB. There's no extra functionality added. Currently the only goal is to simplify, demystify, and make the initialization more robust (and also faster!).

The following Cabal Online Episode 8 server-side services were reverse-engineered and rewritten:
- RockAndRoll (as `crypto`) - fully functional
- GlobalMgrSvr (as `gms`) - functional. Tested with two WorldSvr-s, no longer depends on RockAndRoll
- LoginSvr - (as `login`) - fully functional
- EventMgr (as `event`) - functional stub - doesn't provide any events
- PartySvr - (as `party`) - functional - only basic functionality is implemented. Missing party permissions switching (looting, inviting), mercenaries, nation war, party messages, dungeon stuff (?). Tested with 2 WorldSvr-s and 3 characters

# Building & Running

```bash
$ RUST_LOG=info cargo run -- --resources-dir server/resources/ -s event -s crypto -s gms -s login -s party
```

The above has no dependencies, can be run at any time, and replaces EventMgr, RockAndRoll, GlobalMgrSvr, LoginSvr, and PartySvr within any Cabal Online Episode 8 server instance. The original executables can be removed - they won't be used at all.

The services can be started as separate processes or all at once like in the example above. They all communicate using TCP sockets, just like their original equivalents. They can be started in any order, even before any other Cabal services.
