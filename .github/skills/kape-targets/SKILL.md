---
name: kape-targets
description: Acquire and validate KAPE target collections, including compound targets and existing source-volume shadow copies, without modifying original evidence.
---

# KAPE target acquisition

Use PowerShell 7 on Windows. Obtain the source drive, installed KAPE path,
unused output directories, and evidence-handling authorization first. Do not
change an existing source mount or create/delete its snapshots for these tests.

## Targets and commands

Target names omit `.tkape`. Quote names literally in PowerShell: `'$MFT'`
prevents variable expansion, and `'!BasicCollection'` preserves the compound
target's punctuation. A compound target references other target definitions;
retain those dependencies. Paths authored as `C:\...` in target definitions
are substituted for the drive supplied through `--tsource`.

Inspect the actual installed definitions and KAPE help:

```powershell
& $kape --help
& $kape --tdetail '$MFT'
& $kape --tdetail '!BasicCollection'
```

Use a fresh destination for each acquisition; never reuse an evidence
directory as a mutable test destination:

```powershell
& $kape --tsource S: --target '$MFT' --tdest G:\KapeTests\mft-live --tdd true
& $kape --tsource S: --target '$MFT' --tdest G:\KapeTests\mft-vss --tdd true --vss
& $kape --tsource S: --target '!BasicCollection' --tdest G:\KapeTests\basic-live --tdd true
& $kape --tsource S: --target '!BasicCollection' --tdest G:\KapeTests\basic-vss --tdd true --vss
```

Replace the illustrative source/output paths with explicitly approved paths.
Record the KAPE version, executable SHA-256, target-library hashes, exact
arguments, child exit code, stdout/stderr, and source-volume identity.

KAPE 1.3.0.2 rejected an absolute external target path during testing yet
returned exit 0. For isolated custom-target work, copy the executable and
target library to a dedicated runner, add the target only there, and invoke
its target name. Do not edit the installed KAPE library. Validate the actual
logs and payloads rather than trusting exit status alone.

## VSS and source comparison

Inspect actual log filenames: KAPE can write `*_SkipLog.csv.csv`, not just
`*_SkipLog.csv`. Account separately for deduplicated candidates, copied rows,
and missing-file warnings; deduplication does not demonstrate collection loss.

`--vss` discovers and searches existing source-volume shadow copies. Compare
the source volume GUID with snapshot `VolumeName`; unrelated host snapshots
are not source coverage. Preserve before/after inventories and KAPE's mount,
copy, and skip diagnostics. Do not interpret incomplete, buffered CopyLogs
while KAPE is still running as completed acquisition failures.

`--tdd true` enables SHA-1 deduplication across live and snapshot candidates:
first found wins. Record skipped duplicates and actual contributed payloads.
A snapshot discovered by KAPE does not imply every candidate was retained.
Logged snapshot sources use `VSS<number>\...`; map these to the corresponding
`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<number>\...` only after checking
that snapshot's source-volume identity.

Independently compare collected payload hashes/lengths against the CopyLog.
For accessible source files, also compare the live or corresponding snapshot
stream and exact UTC metadata. Raw NTFS files such as `$MFT` can require KAPE
deferred reads and be inaccessible through ordinary file APIs. Explicitly
label that independent source oracle unavailable; a collected-file/CopyLog
match alone is not independent raw-source verification.

Keep absolute clean-acquisition failures separate from baseline-relative
mutation assertions. Source checks performed after acquisition are not an
atomic acquisition-time oracle. For snapshot comparisons, retain volume GUID,
snapshot ID/device, and resolved same-snapshot path; compare with live data
only as a separately labelled check. Recheck bounded discrepancies for source
read stability before attributing them to collection corruption.

## Verification and disposable mutations

Keep pristine triage data and original logs. Make a separate copy before each
mutation, preserving creation/write timestamps and file attributes. Establish
clean baselines in inventory, hash, timestamp, combined, and full metadata
modes. Check actual process exit codes as well as finding types, counts, and
affected paths.

Exercise adding, deleting, renaming, resizing, a same-size byte edit with both
timestamps restored, creation-only and write-only changes, and a clean copy
afterward. Independently prove content changes by hashes and lengths.
Inventory-only mode does not promise to detect content edits; timestamp-only
mode cannot detect byte edits when timestamps are restored.

For native disk output, mount only disposable copies using the authorized
normal mount procedure. Do not infer missing volumes solely from a failed
read-only mount attempt. Clear read-only payload attributes only on affected
mutation copies. Detach test-owned mounts and remove only explicitly scoped
disposable copies; leave user-owned source mounts intact.

Report unexplained baseline differences as consistency discrepancies, not
proof of tampering. Do not rewrite log destinations or remap drive subtrees
to force a successful verification.

## References

- [Targets](https://ericzimmerman.github.io/KapeDocs/Pages/2.1-Targets.md)
- [Using KAPE](https://ericzimmerman.github.io/KapeDocs/Pages/3.-Using-KAPE.md)
- [Log files](https://ericzimmerman.github.io/KapeDocs/Pages/4.-Log-files.md)

The documentation landing page uses an MDwiki shell; fetch its direct
Markdown pages when investigating details. These instructions summarize
locally exercised commands, not a guarantee for every KAPE version.
