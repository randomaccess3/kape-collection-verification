# KAPE Collection Verification

`Verify-KapeCollection.ps1` compares a directory, mounted disk, or ZIP collection with
its `CopyLog.csv` in both directions. It reports missing files, unlogged files,
invalid mappings, duplicate log entries, and altered KAPE long-path sidecars.
It supports collections stored at a drive root or in any directory. Run with
PowerShell 7 on Windows. The verifier does not mount disks or alter evidence.

## Usage

Show help:

```powershell
.\Verify-KapeCollection.ps1 -h
```

Run an inventory-only comparison:

```powershell
.\Verify-KapeCollection.ps1 -d D:\
```

Run all metadata checks:

```powershell
.\Verify-KapeCollection.ps1 -d "C:\temp\collection" -VerifyMetadata
```

Verify a ZIP without extracting it:

```powershell
.\Verify-KapeCollection.ps1 -ZipPath "G:\collections\collection.zip" -VerifyMetadata
```

Verify a directory extracted from a ZIP, skipping only creation times:

```powershell
.\Verify-KapeCollection.ps1 -d "G:\collections\extracted" -ExtractedZip -VerifyMetadata
```

If the extractor preserved only DOS modification times, explicitly select that
policy and the **acquisition's originating timezone**, not the examiner's:

```powershell
.\Verify-KapeCollection.ps1 -d "G:\collections\extracted" -ExtractedZip -DosExtraction -ZipTimeZoneId "UTC" -VerifyMetadata
```

Available verification modes:

| Flag | Checks |
| --- | --- |
| `-VerifyMetadata` | File sizes, SHA-1 hashes, creation times, and modification times |
| `-VerifyHashes` | SHA-1 hashes |
| `-VerifyTimestamps` | Creation and modification times |

Flags can be combined. Verification displays a progress bar based on the number
of processed CopyLog entries.

## Arguments

| Argument | Description |
| --- | --- |
| `-Directory`, `-d <path>` | Collection directory or mounted collection root; mutually exclusive with `-ZipPath` |
| `-ZipPath <path>` | Direct ZIP input; streams decompressed payloads, with no extraction or whole-payload buffering |
| `-CopyLogPath <path>` | Explicit CopyLog path |
| `-ExtractedZip` | Directory only: skip creation timestamps, not inventory, sizes, hashes, or modification timestamps |
| `-DosExtraction` | Explicit DOS modification-time policy for an extracted directory; requires `-ExtractedZip` and `-ZipTimeZoneId` |
| `-ZipTimeZoneId <id>` | Originating Windows timezone ID for DOS-only modification times |
| `-CopyLogTimingAllowanceSeconds <n>` | Opt-in nonnegative allowance for warning-only CopyLog timing consistency; no default |
| `-CollectionTimeZoneId <id>` | Acquisition timezone for offsetless `CopiedTimestamp` values |
| `-VerifyMetadata` | Verify sizes, SHA-1 hashes, and timestamps |
| `-VerifyHashes` | Verify SHA-1 hashes |
| `-VerifyTimestamps` | Verify creation and modification timestamps |
| `-Help`, `-h` | Print basic help |

Without flags, only inventory is checked: unchanged inventory does **not** prove
unchanged bytes. Use `-VerifyHashes` or `-VerifyMetadata` for content checks.

Use `-CopyLogPath` when the collection root does not contain exactly one
`*_CopyLog.csv`, or to use an independently preserved external log. For a ZIP,
automatic selection requires one CopyLog entry, including under an enclosing
directory. With an external log, one ZIP collection prefix must be inferable
from the logged destinations. Ambiguous selections fail rather than choosing a
collection silently. CopyLog readability, required columns, data rows, and root
inference are checked before evidence enumeration/hashing. Invalid field values
in otherwise usable rows remain findings under the relevant verification mode.
SHA-1 verification uses extended-length Windows paths for long directory paths.

## ZIP timestamp policy

Direct ZIP checks compare **uncompressed** lengths and SHA-1 over decompressed
entry streams, not CRC values or compressed lengths. Unsafe paths are rejected;
duplicate and Windows case-colliding payload names are findings. KAPE sidecar
validation and exclusions apply to both inputs.

Creation timestamps are explicitly unavailable for direct ZIP verification.
Modification checks use exact UTC FILETIMEs from validated central-directory
NTFS (`0x000a`) extra fields when available. They do not depend on host timezone.
The optional, bounded timestamp reader supports single-disk, non-ZIP64 central
directories; unsupported variants, malformed extra fields, and undecodable
legacy non-ASCII names produce explicit limitations, not invented UTC values.
ZIP64 payload inventory/hash/size verification remains handled by .NET
`ZipArchive`; missing optional timestamp support does not disable those checks.

Without usable UTC metadata, a ZIP modification check requires explicit
`-ZipTimeZoneId`. The logged UTC value is converted to the originating local
wall clock and truncated into its DOS two-second bucket. No arbitrary tolerance
or examiner-timezone assumption is used. Missing timezone, ambiguous/nonexistent
DST wall-clock times, or dates outside DOS range make the affected timestamp
comparison explicitly unavailable. Such limitations alone do not fail integrity.

Ordinary directories and mounted disks retain exact UTC creation/modification
comparisons. `-ExtractedZip` skips creation only; modification comparisons remain
exact by default. `-DosExtraction` explicitly opts into the two-second policy
for extractors such as .NET `ZipFile.ExtractToDirectory`, which expose/set DOS
wall-clock values in the extraction host's local timezone. Other extraction
tools may preserve NTFS UTC metadata instead: select the policy matching the
actual tool, not whichever produces a pass. Metadata within a DOS bucket cannot
be distinguished by that comparison.

## CopyLog timing is a heuristic

Timing checks are opt-in. Supply an allowance justified for the acquisition and
packaging workflow; **there is no universal safe number**:

```powershell
# Example only: use a value justified by your own acquisition observations.
$allowance = 2
.\Verify-KapeCollection.ps1 -d "G:\collections\collection" -VerifyHashes -CopyLogTimingAllowanceSeconds $allowance -CollectionTimeZoneId "UTC"
```

The verifier compares the latest valid copy event (not the last CSV row) with
the selected CopyLog's last-write time. Both earlier and later out-of-allowance
writes are suspicious. Actual event offsets are honored; offsetless events
require an explicit acquisition timezone. Invalid/ambiguous event times, missing
timezone/allowance, or untrustworthy log write times are reported as inconclusive.
Direct ZIP uses the **CopyLog entry** timestamp, never the outer archive's time;
DOS-only log timing also needs an explicit timezone and a precision-aware
allowance. Log timing in extracted-ZIP mode is conservatively inconclusive
because extraction may have changed it. A matching companion ConsoleLog, when
available, supplies advisory completion context: copy events or log writes
after completion beyond the supplied allowance warn, but a long packaging phase
after copying does not. Missing, unreadable, invalid, or timezone-ambiguous
completion context is explicitly inconclusive; it is not required for the
event-to-write comparison or treated as an authenticated completion oracle.

Suspicious timing is warning-only: by itself it leaves a clean exit code at `0`.
Payload findings still exit `1`; missing/unusable CopyLogs exit `2` with no PASS.
Preserved timestamps and coordinated edits to the payload and CopyLog can evade
these comparisons. Independently preserve a pre-existing CopyLog hash/signature
for stronger assurance. This tool adds no signing system.

## KAPE-specific handling

- The temporary KAPE target root is inferred from `SourceFile` and
  `DestinationFile`, then removed to map entries into the supplied collection
  directory.
- `LongFileNames\*_OriginalPathInfo.txt` sidecars are checked against the
  corresponding CopyLog source path.
- Root-level `*_CopyLog.csv`, `*_SkipLog.csv`, `*_SkipLog.csv.csv`, and
  `*_ConsoleLog.txt` files are treated as KAPE metadata rather than unlogged
  evidence.
- Root-level `System Volume Information` and `$RECYCLE.BIN` directories are not
  traversed.
- `LastAccessedOnUtc` is not compared because access times can change during
  examination.
- Timestamp comparisons are skipped for NTFS `$Boot` and `$LogFile`.
- Size differences are skipped for KAPE's `$UsnJrnl:$J` to `$J` collection
  behavior.

The script returns exit code `0` when the collection is consistent, `1` when
integrity findings are detected, and `2` when verification cannot be completed.

## Regression tests and coverage

Run the standalone, dependency-free suite under PowerShell 7 on Windows:

```powershell
pwsh -NoProfile -File .\tests\Verify-KapeCollection.Tests.ps1
```

Tests create an unused temporary directory and retain structured results,
child-process arguments, stdout/stderr, and disposable fixtures there. An
explicit `-TestRoot` must not exist already. The suite does not require KAPE or
mount privileges. Real-acquisition validation also exercised KAPE 1.3.0.2
Folder/native ZIP output, .NET ZIP extraction, and native VHD/VHDX collections
under PowerShell 7.6.3.
Windows PowerShell 5.1 is not part of this validation.

Native KAPE VHD and VHDX copies each passed 50 clean/mutation/restore checks
across all five verification modes, plus five clean original-verifier baseline
checks. These were normal read/write mounts of disposable copies, not original
evidence. The earlier apparent absence of partitions/volumes was caused by the
read-only mount procedure; it was not a native-container limitation. Do not
repeat that procedure as a prerequisite to verification. Mount copies normally,
verify their actual collection roots, and dismount them afterward. KAPE payload
files may themselves have a read-only attribute; mutation tests cleared it only
on the affected disposable payloads. Converted-folder VHD/VHDX coverage is also
retained and labelled separately.

Additional mounted-source testing exercised `$MFT` and `!BasicCollection`
with and without `--vss`. Both simple collections passed all 55 clean/mutation
checks each. Untouched compound collections had genuine CopyLog/payload
discrepancies reproduced by both the original and enhanced verifier; they are
not clean acquisitions. All 45 baseline-relative mutation checks per collection
passed without changing those findings or rewriting logs. VSS added snapshot
payloads but did not guarantee a clean integrity result.

The verifier compares a collection with its CopyLog, not atomically with its
live source. Independent post-acquisition source checks may encounter inaccessible
raw NTFS streams or changing source views. Preserve snapshot identity and
compare against that same snapshot, rather than treating expected live/snapshot
differences as failures. See the local
[KAPE target skill](.github/skills/kape-targets/SKILL.md) and
[investigation next steps](docs/Local-Issue-Next-Steps.md).

The CopyLog is a reference, not a signed trust anchor. SHA-1 is the implemented
comparison algorithm, not modern collision-resistant authentication. Empty
directories, excluded metadata/root artifacts, access timestamps, and every byte
of a container are not authenticated. Existing long-path sidecars are validated,
but a deleted unlogged sidecar cannot currently be inferred reliably.
