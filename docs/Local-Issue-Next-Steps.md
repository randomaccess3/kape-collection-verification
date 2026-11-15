# Local issue follow-up

These are investigation notes, not GitHub issues. No external issue or pull
request is requested. Real evidence details and paths remain in local session
artifacts, not this repository.

## Pre-existing collection/log drive-subtree discrepancy

A disposable, hash-validated copy of an existing VHDX has 5,441 logged and
5,441 inventoried payloads, but its original CopyLog maps most files into an
`e` subtree while actual payloads are under `C`. The unchanged verifier reports
10,794 missing/unlogged findings. Three bounded alternate-path samples matched
their logged SHA-1; 44 long-name payloads map normally. This is an unresolved
consistency discrepancy, not proof of tampering or automatically a verifier bug.

Next steps: establish provenance of the collection and its original CopyLog;
determine whether packaging or relocation renamed a drive subtree; compare a
separately preserved original acquisition; and, only with explicit approval,
design any future remapping feature with ambiguity detection. Do not silently
rewrite log destinations or relax root inference to force a pass.

## Native KAPE disk preparation: resolved test-procedure error

KAPE 1.3.0.2 reported successful native VHD and VHDX creation from the seven-file
controlled target. The original read-only mount procedure made those outputs
appear to have no partitions/volumes. Following the user's correction, fresh
copies mounted normally in read/write mode with NTFS volumes, without any disk
initialization or formatting. Both native formats passed all 50 enhanced
clean/mutation/restore checks and five original-verifier baseline modes each.

The earlier native-container limitation and suggested KAPE container-generation
investigation are withdrawn. Preserve the initial diagnostics as provenance of
the test-procedure error, not evidence that native KAPE output is unsupported.
Use normal mounts of disposable copies in future tests, clear payload read-only
file attributes only when deliberately mutating a copy, and dismount afterward.
Converted-folder VHD/VHDX coverage remains separately labelled historical
coverage. Never mount or modify original evidence for these tests.

The native ZIP run also reported a `CannotFindDirectory` packaging warning for
an original long directory after long-name relocation; all seven logged
payloads and the sidecar were independently present/hash-matching. Preserve the
warning for any packaging investigation rather than assuming it indicates
payload loss. KAPE also returned exit 0 for a rejected absolute target path, so
future acquisition automation should validate actual output/logs, not exit
status alone.

## Missing long-name sidecars

The existing verifier validates sidecars that are present. Deleting an unlogged
`*_OriginalPathInfo.txt` sidecar does not currently create a finding if its
payload and CopyLog remain consistent. This behavior predates the ZIP changes.

Next steps: establish from representative KAPE versions whether every GUID
long-name payload requires a sidecar, including packaging exceptions, then
design an explicit missing-sidecar finding and directory/ZIP regression cases.
Do not assume the invariant without real-output evidence.

## Timestamp and trust limits

The optional ZIP UTC metadata reader currently does not decode ZIP64 central
directories. ZIP64 inventory, sizes, and payload SHA-1 still use .NET's archive
reader; affected timestamp checks are explicitly limited. A future extension
should validate ZIP64 bounds/offsets and mixed extra-field encodings with
independently generated archives before expanding support.

CopyLog timing is a warning-only heuristic with a caller-supplied allowance,
not authentication. A coordinated payload/log edit with restored timestamps
can pass. Independently preserving a pre-existing log hash or signature is an
operational next step; a new signing system is outside this change.
