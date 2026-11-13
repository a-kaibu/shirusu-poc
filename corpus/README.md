# Windows reference samples

These entries preserve actual executions of the six-call synchronous file-I/O
Probe, not mocked reports. They are small initial samples, not comprehensive
Windows behavior specifications. Process architecture is distinct from host
architecture; the x86 sample ran under WoW64.

| Entry | Reported Windows build | Process | CI artifact |
| --- | --- | --- | --- |
| `windows/file-io-v1/26100-x86` | 10.0.26100 | x86 | 14027660982 |
| `windows/file-io-v1/26100-x64` | 10.0.26100 | x64 | 14027521780 |
| `windows/file-io-v1/20348-x64` | 10.0.20348 | x64 | 14027676126 |

Source: [CI run 43405537057](https://github.com/a-kaibu/shirusu-poc/actions/runs/43405537057),
commit `b7a330063f4a2e74977f289b51c15b5f5aca25a8`, 2026-11-13 UTC.
Entries retain exact raw reports, execution metadata, inputs and resulting scratch
files from the uploaded artifacts. Environment identity is self-reported by
RtlGetVersion, not independently attested. Recorded absolute executable paths
refer to the original CI machines and are provenance only.

```sh
cargo run -p shirusu-probe -- corpus compare \
  corpus/windows/file-io-v1/26100-x86 \
  corpus/windows/file-io-v1/20348-x64
```

All three entries have identical normalized observations. The loader verifies content
hashes and recomputes observations before comparing. Preserve raw bytes: newline
conversion changes the report digest. New runs belong in new directories; do not
replace existing evidence. See [the format and scope](../docs/reference-corpus.md).

## File creation and error observations

`windows/file-errors-v1` preserves the fourteen-call error/disposition Probe from
[CI run 43410242785](https://github.com/a-kaibu/shirusu-poc/actions/runs/43410242785),
commit `cc86db26b220946391a58102b89d6733b374ebab`, 2026-11-13 UTC.

| Entry | Process | CI artifact |
| --- | --- | --- |
| `windows/file-errors-v1/26100-x86` | x86 under WoW64 | 14029686535 |
| `windows/file-errors-v1/26100-x64` | x64 | 14028289685 |
| `windows/file-errors-v1/20348-x64` | x64 | 14028918089 |

All three normalized sequences agree: missing files report error 2, duplicate
CREATE_NEW reports 80, exclusive sharing conflicts report 32, and successful
OPEN_ALWAYS / CREATE_ALWAYS on the existing file report 183. OPEN_ALWAYS on a
new file reports 0. These are observations for this exact Probe and environment.
The failed-open value is also the current-process pseudo-handle; closing it
returned success in these runs. The Probe records that result without assuming
that every INVALID_HANDLE_VALUE passed to CloseHandle must fail.
