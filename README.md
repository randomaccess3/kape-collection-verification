# KAPE Collection Verification

`Test-KapeCollection.ps1` compares a mounted or extracted KAPE collection with
its `CopyLog.csv` in both directions. It reports missing files, unlogged files,
invalid mappings, duplicate log entries, and altered KAPE long-path sidecars.
It supports collections stored at a drive root or in any directory.

## Usage

Show help:

```powershell
.\Test-KapeCollection.ps1 -h
```

Run an inventory-only comparison:

```powershell
.\Test-KapeCollection.ps1 -d D:\
```

Run all metadata checks:

```powershell
.\Test-KapeCollection.ps1 -d "C:\temp\collection" -VerifyMetadata
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
| `-Directory`, `-d <path>` | Required collection root |
| `-CopyLogPath <path>` | Explicit CopyLog path |
| `-VerifyMetadata` | Verify sizes, SHA-1 hashes, and timestamps |
| `-VerifyHashes` | Verify SHA-1 hashes |
| `-VerifyTimestamps` | Verify creation and modification timestamps |
| `-Help`, `-h` | Print basic help |

Use `-CopyLogPath` when the collection root does not contain exactly one
`*_CopyLog.csv`. SHA-1 verification uses extended-length Windows paths so files
whose paths exceed 260 characters can be checked under Windows PowerShell 5.1.

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
