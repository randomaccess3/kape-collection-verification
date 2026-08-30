# KAPE Collection Verification

`Test-KapeCollection.ps1` compares a mounted or extracted KAPE collection with
its `CopyLog.csv` in both directions. It reports missing files, unlogged files,
invalid mappings, duplicates, and altered KAPE long-path sidecars.

## Usage

Run a structure-only comparison:

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

Use `-CopyLogPath` when the collection root does not contain exactly one
`*_CopyLog.csv` file.

The script returns exit code `0` when the collection is consistent, `1` when
integrity findings are detected, and `2` when verification cannot be completed.
