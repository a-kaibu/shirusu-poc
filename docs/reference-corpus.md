# Versioned Windows reference corpus (v1)

`shirusu-probe corpus record` runs a JSON Probe in a fresh working directory and
stores a complete, version-identified result. `corpus compare` compares entries
for the same canonical Probe, including entries from different Windows builds
or x86/x64 processes:

```text
shirusu-probe corpus record probe.json --runner C:\tools\shirusu-test.exe --out entry-26100-x64 --label "Windows CI"
shirusu-probe corpus compare entry-26100-x64 entry-20348-x64
```

The output directory must not exist. `probe.json` holds the canonical executed
specification; `run/` preserves stdout, stderr, execution metadata and the fresh
working directory. `entry.json` is written only after the report is complete and
bound to the specification's name, ordered calls and indices. Failed execution
leaves evidence but no valid entry. An incomplete/aborted assertion sequence is
not a reference result; omit assertions when intentionally exploring failures.

BLAKE3 digests bind the canonical Probe and exact raw report bytes. Every load
recomputes observations and the complete manifest from fixed local paths. A
modified or incomplete entry is rejected. Object key order does not change the
Probe identity; name, inputs, expectations, rules and call order do. Hashes
provide integrity checks, not authentication or protection against forged data.

The initial scope is CreateFileW, ReadFile, WriteFile and CloseHandle with normal
synchronous files, local ASCII basenames, bounded (4096-byte) buffers, explicit
output counts and handles created earlier in the Probe. Device names, external
paths, raw handle integers and asynchronous operations are rejected. The runner
is trusted executable code; fresh working directories are not an OS sandbox.
Remote wrappers must manage their own descendants and actual scratch directory.

Comparison normalizes successful HANDLE addresses and nonzero BOOL values,
ignores stale LastError after successful ReadFile/WriteFile/CloseHandle, and
compares actual read bytes rather than unused buffer tails. CreateFileW preserves
failure errors and successful CREATE_ALWAYS/OPEN_ALWAYS errors. Reported
truncation, missing counts and counts exceeding the request are rejected.
Differences are observations, not proof that either implementation is wrong;
later steps can be affected by earlier differences. Compare prints JSON and exits
0 for a valid comparison, including differences, and 2 for incompatible/damaged
entries or invalid usage. Record errors exit 1 (argument errors exit 2).

Environment identity comes from the runner's RtlGetVersion report. It includes
Windows version/build and process architecture; this does not attest that the
machine runs native Windows (a compatibility layer can report the same values).
Labels and execution metadata provide provenance context, not attestation.

Windows CI records the six-call write/reopen/read Probe and a separate
14-call file-open/error Probe (missing file, exclusive sharing, duplicate create,
CREATE_ALWAYS and OPEN_ALWAYS with existing/new files) on Windows x64,
WoW64 x86 and Server 2022 and uploads `windows-reference-corpus-*` artifacts for
30 days. Initial real entries for builds 26100 (x86/x64) and 20348 (x64) are also retained in
[`corpus/`](../corpus/README.md), with CI provenance and exact raw bytes. These
are small reference samples, not comprehensive API coverage. Broader probes,
additional Windows releases and automated corpus curation remain future work.
