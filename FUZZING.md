# Fuzzing triage

When the scheduled "Continuous Fuzzing" run fails:

1. Open the failed run, download the `fuzz-crashes` artifact (crash/timeout/oom file + fuzz.log).
2. Reproduce locally: `npx jazzer fuzz/searchQuery.fuzz.js --sync -- path/to/crash-file`
3. Fix the bug in `src/lib/searchQuery.js`.
4. Copy the crash file into `fuzz/regression/` and add a unit test in `test/` using the exact input.
5. Push. The next run replays every file in `fuzz/regression/` before fuzzing.
6. Close the auto-opened issue and link the fixing commit.

Time budget: 600 s per nightly run, corpus cached between runs (see FUZZING_REPORT.md).
