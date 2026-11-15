<#
.SYNOPSIS
Verifies a directory or ZIP KAPE collection against its CopyLog.

.DESCRIPTION
Checks both directions: every CopyLog entry must exist with the recorded size,
and every file below the collection directory must have a CopyLog entry.
CopyLog, SkipLog, and ConsoleLog files located directly in the collection
directory are excluded from the collected-file inventory. Its System Volume
Information and $RECYCLE.BIN directories are also excluded because they belong
to the mounted volume rather than the collection.

The temporary KAPE target root is inferred by correlating SourceFile and
DestinationFile. That prefix is then removed from every DestinationFile. This
preserves KAPE's renamed files, including alternate data streams and entries in
LongFileNames. For example, C:\temp\t\E\$Extend\$J maps to
D:\E\$Extend\$J when -d D:\ is used.

LongFileNames\*_OriginalPathInfo.txt sidecars are validated against the
SourceFile of their matching GUID-named payload before being excluded from the
unlogged-file inventory.

The recorded size comparison is skipped for the NTFS $UsnJrnl:$J stream because
KAPE's collected $J file can have a different logical length.

.PARAMETER Directory
The root directory of the KAPE collection, such as D:\ or C:\temp\t.

.PARAMETER CopyLogPath
The CopyLog CSV to use. If omitted, the script requires exactly one
*_CopyLog.csv file directly below the collection directory.

.PARAMETER ZipPath
Verify a ZIP directly using decompressed entry streams, without extraction.

.PARAMETER ExtractedZip
For an extracted ZIP directory, skip creation timestamps only.

.PARAMETER ZipTimeZoneId
Explicit originating Windows timezone for DOS-only ZIP timestamps.

.PARAMETER DosExtraction
Use DOS two-second wall-clock timestamp comparisons for an extracted ZIP.
Requires ExtractedZip and ZipTimeZoneId.

.PARAMETER CopyLogTimingAllowanceSeconds
Opt-in, nonnegative timing allowance. Suspicious timing is warning-only.
There is no universal default allowance.

.PARAMETER CollectionTimeZoneId
Explicit acquisition timezone for offsetless CopiedTimestamp values.

.PARAMETER VerifyMetadata
Verifies file sizes, SHA-1 hashes, and filesystem timestamps.

.PARAMETER VerifyHashes
Calculates SHA-1 for every logged file and compares it with SourceFileSha1.

.PARAMETER VerifyTimestamps
Compares each file's creation and modification UTC timestamps with CreatedOnUtc
and ModifiedOnUtc in the CopyLog. LastAccessedOnUtc is intentionally ignored,
as are timestamps for the NTFS $Boot and $LogFile metadata files.

.PARAMETER Help
Prints basic usage and the available arguments.

.EXAMPLE
.\Verify-KapeCollection.ps1 -d D:\

.EXAMPLE
.\Verify-KapeCollection.ps1 -d C:\temp\t -VerifyMetadata

.NOTES
Exit code 0 means the collection is consistent, 1 means integrity findings
were detected, and 2 means verification could not be completed.
#>
#requires -Version 7.0
[CmdletBinding(DefaultParameterSetName = 'Verify')]
param(
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Verify')]
    [Alias('d')]
    [ValidateNotNullOrEmpty()]
    [string]$Directory,

    [Parameter(Mandatory = $true, ParameterSetName = 'Zip')]
    [ValidateNotNullOrEmpty()]
    [string]$ZipPath,

    [Parameter(ParameterSetName = 'Verify')]
    [Parameter(ParameterSetName = 'Zip')]
    [ValidateNotNullOrEmpty()]
    [string]$CopyLogPath,

    [Parameter(ParameterSetName = 'Verify')]
    [Parameter(ParameterSetName = 'Zip')]
    [switch]$VerifyMetadata,

    [Parameter(ParameterSetName = 'Verify')]
    [Parameter(ParameterSetName = 'Zip')]
    [switch]$VerifyHashes,

    [Parameter(ParameterSetName = 'Verify')]
    [Parameter(ParameterSetName = 'Zip')]
    [switch]$VerifyTimestamps,

    [Parameter(ParameterSetName = 'Verify')]
    [switch]$ExtractedZip,

    [Parameter(ParameterSetName = 'Verify')]
    [switch]$DosExtraction,

    [Parameter(ParameterSetName = 'Verify')]
    [Parameter(ParameterSetName = 'Zip')]
    [string]$ZipTimeZoneId,

    [Parameter(ParameterSetName = 'Verify')]
    [Parameter(ParameterSetName = 'Zip')]
    [ValidateRange(0, 3155760000)]
    [double]$CopyLogTimingAllowanceSeconds,

    [Parameter(ParameterSetName = 'Verify')]
    [Parameter(ParameterSetName = 'Zip')]
    [string]$CollectionTimeZoneId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Help')]
    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($Help) {
    Write-Output @'
KAPE Collection Verification

Usage:
  .\Verify-KapeCollection.ps1 -d <directory> [options]
  .\Verify-KapeCollection.ps1 -ZipPath <archive.zip> [options]
  .\Verify-KapeCollection.ps1 -h

Arguments:
  -Directory, -d <path>   KAPE collection root directory (required).
  -CopyLogPath <path>     CopyLog CSV path. By default, the script locates
                          exactly one *_CopyLog.csv in the collection root.
  -VerifyMetadata         Verify file sizes, SHA-1 hashes, and timestamps.
  -VerifyHashes           Verify SHA-1 hashes only.
  -VerifyTimestamps       Verify creation and modification timestamps only.
  -ZipPath <path>          Verify ZIP streams directly (instead of -Directory).
  -ExtractedZip            Directory only: skip creation timestamps.
  -DosExtraction          Extracted ZIP modification times use DOS precision;
                          requires -ExtractedZip and -ZipTimeZoneId.
  -ZipTimeZoneId <id>      Originating timezone for DOS wall-clock timestamps.
  -CopyLogTimingAllowanceSeconds <n>
                          Opt-in warning-only timing check; no default bound.
  -CollectionTimeZoneId <id>
                          Acquisition timezone for offsetless copy events.
  -Help, -h               Print this help output.

Without a verification flag, the script compares only the CopyLog and file
inventory.
'@
    exit 0
}

$requiredColumns = @(
    'CopiedTimestamp',
    'SourceFile',
    'DestinationFile',
    'FileSize',
    'SourceFileSha1',
    'DeferredCopy',
    'CreatedOnUtc',
    'ModifiedOnUtc',
    'LastAccessedOnUtc',
    'CopyDuration'
)

$findings = New-Object 'System.Collections.Generic.List[object]'
$archive = $null
$zipMetadataStream = $null
$isZip = $PSCmdlet.ParameterSetName -eq 'Zip'
$timingEnabled = $PSBoundParameters.ContainsKey('CopyLogTimingAllowanceSeconds')
$timestampLimitations = [Collections.Generic.HashSet[string]]::new()

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Details
    )

    $findings.Add([pscustomobject]@{
        Type    = $Type
        Path    = $Path
        Details = $Details
    })
}

function Get-Sha1Hash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith('\\')) {
        $extendedPath = '\\?\UNC\' + $fullPath.TrimStart('\')
    }
    else {
        $extendedPath = '\\?\' + $fullPath
    }

    $stream = New-Object IO.FileStream(
        $extendedPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        (
            [IO.FileShare]::ReadWrite -bor
            [IO.FileShare]::Delete
        )
    )
    $sha1 = [Security.Cryptography.SHA1]::Create()
    try {
        return [BitConverter]::ToString(
            $sha1.ComputeHash($stream)
        ).Replace('-', '')
    }
    finally {
        $sha1.Dispose()
        $stream.Dispose()
    }
}

function Get-EntryHash {
    param([object]$Item)
    if (-not $isZip) {
        return Get-Sha1Hash -Path $Item.FullName
    }
    $stream = $Item.ZipEntry.Open()
    $sha1 = [Security.Cryptography.SHA1]::Create()
    try {
        return [Convert]::ToHexString($sha1.ComputeHash($stream))
    }
    finally {
        $sha1.Dispose()
        $stream.Dispose()
    }
}

function Read-EntryText {
    param([object]$Item)
    if (-not $isZip) {
        return Get-Content -LiteralPath $Item.FullName -Raw
    }
    $reader = [IO.StreamReader]::new($Item.ZipEntry.Open())
    try { return $reader.ReadToEnd() }
    finally { $reader.Dispose() }
}

function Get-ZipUtcTimes {
    param([IO.Stream]$Stream)
    # Read only bounded directory records, never payloads. ZIP64 remains usable
    # through ZipArchive, but this optional metadata reader does not decode it.
    $times = [Collections.Generic.Dictionary[string,datetime]]::new([StringComparer]::Ordinal)
    $reader = [IO.BinaryReader]::new($Stream, [Text.Encoding]::UTF8, $true)
    try {
        $tailLength = [int][Math]::Min(65557, $Stream.Length)
        $Stream.Position = $Stream.Length - $tailLength
        $tail = $reader.ReadBytes($tailLength)
        $end = -1
        for ($i = $tail.Length - 22; $i -ge 0; $i--) {
            if ([BitConverter]::ToUInt32($tail, $i) -eq 0x06054b50 -and
                $i + 22 + [BitConverter]::ToUInt16($tail, $i + 20) -eq $tail.Length) {
                $end = $i
                break
            }
        }
        if ($end -lt 0) { throw 'ZIP end-of-directory record not found.' }
        $count = [BitConverter]::ToUInt16($tail, $end + 10)
        $directorySize = [BitConverter]::ToUInt32($tail, $end + 12)
        $directoryOffset = [BitConverter]::ToUInt32($tail, $end + 16)
        if ($count -eq 65535 -or $directoryOffset -eq [uint32]::MaxValue -or
            $directorySize -eq [uint32]::MaxValue) {
            throw 'ZIP64 UTC timestamp metadata is not decoded.'
        }
        if ([BitConverter]::ToUInt16($tail, $end + 4) -ne 0 -or
            [BitConverter]::ToUInt16($tail, $end + 6) -ne 0 -or
            [BitConverter]::ToUInt16($tail, $end + 8) -ne $count) {
            throw 'Multi-disk ZIP timestamp metadata is unsupported.'
        }
        $directoryEnd = [long]$directoryOffset + $directorySize
        if ($directoryEnd -gt $Stream.Length - $tailLength + $end) {
            throw 'ZIP central-directory bounds are invalid.'
        }
        $Stream.Position = $directoryOffset
        for ($index = 0; $index -lt $count; $index++) {
            if ($Stream.Position + 46 -gt $directoryEnd) { throw 'Truncated ZIP directory record.' }
            $header = $reader.ReadBytes(46)
            if ([BitConverter]::ToUInt32($header, 0) -ne 0x02014b50) { throw 'Invalid ZIP directory signature.' }
            $nameLength = [BitConverter]::ToUInt16($header, 28)
            $extraLength = [BitConverter]::ToUInt16($header, 30)
            $commentLength = [BitConverter]::ToUInt16($header, 32)
            if ($Stream.Position + $nameLength + $extraLength + $commentLength -gt $directoryEnd) {
                throw 'ZIP directory field exceeds record bounds.'
            }
            $nameBytes = $reader.ReadBytes($nameLength)
            $flags = [BitConverter]::ToUInt16($header, 8)
            # Match ZipArchive's UTF-8 default; legacy non-ASCII names are not
            # assigned a guessed timestamp.
            if (($flags -band 0x800) -eq 0 -and @($nameBytes | Where-Object { $_ -gt 127 }).Count) {
                $name = $null
            }
            else {
                $name = [Text.UTF8Encoding]::new($false, $true).GetString($nameBytes)
            }
            $extra = $reader.ReadBytes($extraLength)
            $Stream.Position += $commentLength
            $position = 0
            $modified = $null
            while ($position -lt $extra.Length) {
                if ($position + 4 -gt $extra.Length) { throw 'Truncated ZIP extra-field header.' }
                $tag = [BitConverter]::ToUInt16($extra, $position)
                $length = [BitConverter]::ToUInt16($extra, $position + 2)
                $position += 4
                $limit = $position + $length
                if ($limit -gt $extra.Length) { throw 'Truncated ZIP extra field.' }
                if ($tag -eq 10) {
                    if ($length -lt 4) { throw 'Invalid ZIP NTFS extra field.' }
                    $attribute = $position + 4
                    while ($attribute -lt $limit) {
                        if ($attribute + 4 -gt $limit) { throw 'Truncated ZIP NTFS attribute.' }
                        $attributeTag = [BitConverter]::ToUInt16($extra, $attribute)
                        $attributeLength = [BitConverter]::ToUInt16($extra, $attribute + 2)
                        $attribute += 4
                        if ($attribute + $attributeLength -gt $limit) { throw 'Invalid ZIP NTFS attribute bounds.' }
                        if ($attributeTag -eq 1) {
                            if ($attributeLength -ne 24 -or $null -ne $modified) { throw 'Ambiguous ZIP NTFS timestamps.' }
                            $modified = [datetime]::FromFileTimeUtc([BitConverter]::ToInt64($extra, $attribute))
                        }
                        $attribute += $attributeLength
                    }
                }
                $position = $limit
            }
            if ($null -ne $name -and $null -ne $modified) {
                if ($times.ContainsKey($name)) { throw 'Duplicate ZIP UTC timestamp names.' }
                $times.Add($name, $modified)
            }
        }
        if ($Stream.Position -ne $directoryEnd) { throw 'Unexpected trailing ZIP directory data.' }
        return ,$times
    }
    finally { $reader.Dispose() }
}

function Get-ZipItem {
    param([IO.Compression.ZipArchiveEntry]$Entry, [string]$RelativePath)
    $fullPath = [IO.Path]::GetFullPath((Join-Path $collectionRoot $RelativePath))
    $utcAvailable = $zipUtcTimes.ContainsKey($Entry.FullName)
    [pscustomobject]@{
        FullName = $fullPath
        Name = [IO.Path]::GetFileName($fullPath)
        DirectoryName = [IO.Path]::GetDirectoryName($fullPath)
        PSIsContainer = $false
        Attributes = [IO.FileAttributes]::Normal
        Length = $Entry.Length
        ZipEntry = $Entry
        UtcAvailable = $utcAvailable
        LastWriteTimeUtc = $(if ($utcAvailable) { $zipUtcTimes[$Entry.FullName] } else { [datetime]::MinValue })
    }
}

function Convert-CollectionTimestamp {
    param([string]$Value)
    $valueTrimmed = $Value.Trim()
    if ($valueTrimmed -match '(?i)(Z|[+-]\d{2}:\d{2})$') {
        return [DateTimeOffset]::Parse($valueTrimmed, [cultureinfo]::InvariantCulture).UtcDateTime
    }
    if ($null -eq $collectionTimeZone) { throw 'Offsetless copy events require -CollectionTimeZoneId.' }
    $wall = [datetime]::SpecifyKind(
        [datetime]::Parse($valueTrimmed, [cultureinfo]::InvariantCulture),
        [DateTimeKind]::Unspecified
    )
    if ($collectionTimeZone.IsInvalidTime($wall) -or $collectionTimeZone.IsAmbiguousTime($wall)) {
        throw 'Copy event is ambiguous or invalid in the collection timezone.'
    }
    return [TimeZoneInfo]::ConvertTimeToUtc($wall, $collectionTimeZone)
}

function Test-CopyLogTiming {
    param(
        [object[]]$Rows,
        [Nullable[datetime]]$LogWriteUtc,
        [string]$ConsoleText,
        [string]$ConsoleIssue
    )
    if (-not $timingEnabled) {
        Write-Output 'CopyLog timing: inconclusive (no allowance supplied; heuristic not enabled).'
        return
    }
    if ($null -eq $LogWriteUtc) {
        Write-Warning 'CopyLog timing inconclusive: no trustworthy UTC log modification time.'
        return
    }
    try {
        $latest = [datetime]::MinValue
        foreach ($row in $Rows) {
            $eventTime = Convert-CollectionTimestamp ([string]$row.CopiedTimestamp)
            if ($eventTime -gt $latest) { $latest = $eventTime }
        }
        $delta = ($LogWriteUtc - $latest).TotalSeconds
        if ([Math]::Abs($delta) -gt $CopyLogTimingAllowanceSeconds) {
            Write-Warning (
                "CopyLog timing is suspicious: last write minus latest copy event = $delta seconds; " +
                "allowance = $CopyLogTimingAllowanceSeconds seconds. This heuristic does not authenticate the log."
            )
        }
        else {
            Write-Output 'CopyLog timing: within the supplied allowance (not authentication).'
        }
    }
    catch {
        Write-Warning "CopyLog timing inconclusive: $($_.Exception.Message)"
        return
    }
    if ($ConsoleIssue) {
        Write-Warning "ConsoleLog completion context inconclusive: $ConsoleIssue"
        return
    }
    try {
        $completion = [datetime]::MinValue
        $matches = [regex]::Matches(
            $ConsoleText,
            '(?m)^\[(?<Time>[^\]\r\n]+?)\s+\|\s+INF\]\s+Total execution time:'
        )
        if ($matches.Count -eq 0) { throw 'No recognized completion timestamp.' }
        foreach ($match in $matches) {
            $time = Convert-CollectionTimestamp $match.Groups['Time'].Value
            if ($time -gt $completion) { $completion = $time }
        }
        # Completion may legitimately follow the CopyLog by a long packaging
        # phase. Only events/writes after completion are suspicious here.
        if (($latest - $completion).TotalSeconds -gt $CopyLogTimingAllowanceSeconds -or
            ($LogWriteUtc - $completion).TotalSeconds -gt $CopyLogTimingAllowanceSeconds) {
            Write-Warning 'CopyLog timing is suspicious relative to ConsoleLog completion (advisory context, not authentication).'
        }
        else {
            Write-Output 'ConsoleLog completion context: no post-completion inconsistency detected (not authentication).'
        }
    }
    catch {
        Write-Warning "ConsoleLog completion context inconclusive: $($_.Exception.Message)"
    }
}

function Test-LoggedTimestamp {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Field,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$LoggedValue,

        [Parameter(Mandatory = $true)]
        [datetime]$ActualValueUtc,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [int]$RowNumber,

        [switch]$DosWallClock
    )

    [DateTimeOffset]$loggedTimestamp = [DateTimeOffset]::MinValue
    $styles = (
        [Globalization.DateTimeStyles]::AssumeUniversal -bor
        [Globalization.DateTimeStyles]::AdjustToUniversal
    )
    $validTimestamp = [DateTimeOffset]::TryParse(
        $LoggedValue.Trim(),
        [Globalization.CultureInfo]::InvariantCulture,
        $styles,
        [ref]$loggedTimestamp
    )

    if (-not $validTimestamp) {
        Add-Finding -Type 'InvalidLoggedTimestamp' `
            -Path $Path `
            -Details "CSV row $RowNumber has invalid $Field value '$LoggedValue'."
        return
    }

    $actualTimestamp = $ActualValueUtc
    $expectedTimestamp = $loggedTimestamp.UtcDateTime
    if ($DosWallClock) {
        $actualTimestamp = [datetime]::SpecifyKind($actualTimestamp, [DateTimeKind]::Unspecified)
        $expectedTimestamp = [TimeZoneInfo]::ConvertTimeFromUtc($expectedTimestamp, $zipTimeZone)
        $expectedTimestamp = [datetime]::SpecifyKind($expectedTimestamp, [DateTimeKind]::Unspecified)
        if ($zipTimeZone.IsAmbiguousTime($expectedTimestamp) -or $zipTimeZone.IsInvalidTime($expectedTimestamp) -or
            $zipTimeZone.IsAmbiguousTime($actualTimestamp) -or $zipTimeZone.IsInvalidTime($actualTimestamp)) {
            [void]$timestampLimitations.Add('DOS modification time falls in an ambiguous/invalid timezone interval.')
            return
        }
        if ($expectedTimestamp.Year -lt 1980 -or $expectedTimestamp.Year -gt 2107) {
            [void]$timestampLimitations.Add('Modification time is outside the DOS ZIP timestamp range.')
            return
        }
        $expectedTimestamp = $expectedTimestamp.AddTicks(-($expectedTimestamp.Ticks % [TimeSpan]::FromSeconds(2).Ticks))
    }
    else { $actualTimestamp = $actualTimestamp.ToUniversalTime() }
    if ($expectedTimestamp.Ticks -ne $actualTimestamp.Ticks) {
        Add-Finding -Type 'TimestampMismatch' `
            -Path $Path `
            -Details (
                "$Field - CopyLog: " +
                "$($expectedTimestamp.ToString('o')); collection: " +
                "$($actualTimestamp.ToString('o'))."
            )
    }
}

function Get-DestinationRoot {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Rows
    )

    $rootCounts = @{}
    foreach ($row in $Rows) {
        $source = ([string]$row.SourceFile).Trim().Replace('/', '\')
        $destination = ([string]$row.DestinationFile).Trim().Replace('/', '\')
        if ($source -notmatch '^([A-Za-z]):\\(.+)$') {
            continue
        }

        $sourceRelativePath = '{0}\{1}' -f $Matches[1], $Matches[2]
        $suffix = '\' + $sourceRelativePath
        if (
            $destination.Length -le $suffix.Length -or
            -not $destination.EndsWith(
                $suffix,
                [StringComparison]::OrdinalIgnoreCase
            )
        ) {
            continue
        }

        $candidateRoot = $destination.Substring(
            0,
            $destination.Length - $suffix.Length
        ).TrimEnd('\')
        if ($candidateRoot -match '^[A-Za-z]:$') {
            $candidateRoot += '\'
        }
        elseif ($candidateRoot -notmatch '^[A-Za-z]:\\') {
            continue
        }

        if ($rootCounts.ContainsKey($candidateRoot)) {
            $rootCounts[$candidateRoot]++
        }
        else {
            $rootCounts[$candidateRoot] = 1
        }
    }

    if ($rootCounts.Count -eq 0) {
        throw (
            'Could not infer KAPE''s temporary destination root from the ' +
            'SourceFile and DestinationFile columns.'
        )
    }

    $rankedRoots = @(
        $rootCounts.GetEnumerator() |
            Sort-Object Value -Descending
    )
    if (
        $rankedRoots.Count -gt 1 -and
        $rankedRoots[0].Value -eq $rankedRoots[1].Value
    ) {
        throw (
            'More than one temporary destination root is equally likely: ' +
            "$($rankedRoots[0].Key), $($rankedRoots[1].Key)"
        )
    }

    return [string]$rankedRoots[0].Key
}

function Get-CollectionPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [Parameter(Mandatory = $true)]
        [string]$DestinationRoot,

        [Parameter(Mandatory = $true)]
        [string]$CollectionRoot
    )

    $normalizedDestination = $Destination.Trim().Replace('/', '\')
    $destinationPrefix = $DestinationRoot.TrimEnd('\') + '\'
    if ($normalizedDestination.StartsWith(
            $destinationPrefix,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        $relativePath = $normalizedDestination.Substring($destinationPrefix.Length)
    }
    else {
        throw "Destination is outside the inferred KAPE target root '$DestinationRoot'."
    }

    if ([string]::IsNullOrWhiteSpace($relativePath)) {
        throw 'The destination does not identify a collected file.'
    }

    $candidate = [IO.Path]::GetFullPath((Join-Path $CollectionRoot $relativePath))
    $rootPrefix = $CollectionRoot.TrimEnd('\') + '\'
    if (-not $candidate.StartsWith(
            $rootPrefix,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "The mapped path escapes the collection directory."
    }

    return $candidate
}

try {
    $zipTimeZone = $null
    $collectionTimeZone = $null
    if ($ZipTimeZoneId) { $zipTimeZone = [TimeZoneInfo]::FindSystemTimeZoneById($ZipTimeZoneId) }
    if ($CollectionTimeZoneId) { $collectionTimeZone = [TimeZoneInfo]::FindSystemTimeZoneById($CollectionTimeZoneId) }
    if ($DosExtraction -and (-not $ExtractedZip -or $null -eq $zipTimeZone)) {
        throw '-DosExtraction requires -ExtractedZip and -ZipTimeZoneId.'
    }
    if ($isZip) {
        $resolvedZip = (Resolve-Path -LiteralPath $ZipPath).ProviderPath
        $archive = [IO.Compression.ZipFile]::OpenRead($resolvedZip)
        $collectionRoot = [IO.Path]::GetFullPath($resolvedZip + '.entries')
        $zipEntries = @($archive.Entries)
        foreach ($entry in $zipEntries) {
            $name = $entry.FullName.Replace('/', '\')
            if ([string]::IsNullOrWhiteSpace($name) -or $name -match '(^\\|:|(^|\\)\.\.?($|\\)|\\\\)' -or
                $name -match '[\x00-\x1f]' -or $name.TrimEnd('\') -match '(^|\\)[^\\]*[. ]($|\\)') {
                throw "Unsafe ZIP entry path: $($entry.FullName)"
            }
        }
        $zipMetadataStream = [IO.File]::OpenRead($resolvedZip)
        try { $zipUtcTimes = Get-ZipUtcTimes -Stream $zipMetadataStream }
        catch {
            Write-Warning "ZIP UTC timestamp metadata unavailable: $($_.Exception.Message)"
            $zipUtcTimes = [Collections.Generic.Dictionary[string,datetime]]::new([StringComparer]::Ordinal)
        }
        finally {
            $zipMetadataStream.Dispose()
            $zipMetadataStream = $null
        }
    }
    else {
        $resolvedMount = (Resolve-Path -LiteralPath $Directory).ProviderPath
        $mountItem = Get-Item -LiteralPath $resolvedMount -Force
        if (-not $mountItem.PSIsContainer) {
            throw "Directory is not a directory: $Directory"
        }
        $collectionRoot = [IO.Path]::GetFullPath($resolvedMount)
    }
    $collectionRootForComparison = $collectionRoot.TrimEnd('\')
    $internalCopyLog = $null
    $zipRootPrefix = ''
    if ($PSBoundParameters.ContainsKey('CopyLogPath')) {
        $resolvedCopyLog = (Resolve-Path -LiteralPath $CopyLogPath).ProviderPath
    }
    elseif ($isZip) {
        $copyLogs = @($zipEntries | Where-Object {
            [IO.Path]::GetFileName($_.FullName.Replace('/', '\')) -like '*_CopyLog.csv'
        })
        if ($copyLogs.Count -ne 1) {
            throw "Expected exactly one CopyLog ZIP entry; found $($copyLogs.Count). Specify -CopyLogPath explicitly."
        }
        $internalCopyLog = $copyLogs[0]
        $normalizedLogName = $internalCopyLog.FullName.Replace('/', '\')
        $zipRootPrefix = $normalizedLogName.Substring(
            0, $normalizedLogName.Length - [IO.Path]::GetFileName($normalizedLogName).Length
        )
        $resolvedCopyLog = "$resolvedZip!$($internalCopyLog.FullName)"
    }
    else {
        $copyLogs = @(
            Get-ChildItem -LiteralPath $collectionRoot -File -Force |
                Where-Object { $_.Name -like '*_CopyLog.csv' }
        )
        if ($copyLogs.Count -ne 1) {
            throw (
                "Expected exactly one *_CopyLog.csv in {0}; found {1}. " +
                'Specify -CopyLogPath explicitly.'
            ) -f $collectionRoot, $copyLogs.Count
        }
        $resolvedCopyLog = $copyLogs[0].FullName
    }

    $logWriteUtc = $null
    if ($null -ne $internalCopyLog) {
        $logReader = [IO.StreamReader]::new($internalCopyLog.Open())
        try { $rows = @($logReader.ReadToEnd() | ConvertFrom-Csv) }
        finally { $logReader.Dispose() }
        if ($zipUtcTimes.ContainsKey($internalCopyLog.FullName)) {
            $logWriteUtc = $zipUtcTimes[$internalCopyLog.FullName]
        }
        elseif ($null -ne $zipTimeZone) {
            $wall = [datetime]::SpecifyKind($internalCopyLog.LastWriteTime.DateTime, [DateTimeKind]::Unspecified)
            if (-not $zipTimeZone.IsAmbiguousTime($wall) -and -not $zipTimeZone.IsInvalidTime($wall)) {
                $logWriteUtc = [TimeZoneInfo]::ConvertTimeToUtc($wall, $zipTimeZone)
                Write-Warning 'CopyLog timing uses DOS ZIP modification precision; include packaging precision in your allowance.'
            }
        }
    }
    else {
        $copyLogItem = Get-Item -LiteralPath $resolvedCopyLog -Force
        if ($copyLogItem.PSIsContainer) {
            throw "CopyLogPath is not a file: $resolvedCopyLog"
        }
        $rows = @(Import-Csv -LiteralPath $resolvedCopyLog)
        if (-not $ExtractedZip) { $logWriteUtc = $copyLogItem.LastWriteTimeUtc }
        else {
            Write-Warning 'Extracted CopyLog timing is inconclusive: extraction may rewrite its modification time.'
        }
    }
    if ($rows.Count -eq 0) {
        throw "The CopyLog contains no data rows: $resolvedCopyLog"
    }

    $columns = @($rows[0].PSObject.Properties.Name)
    $missingColumns = @($requiredColumns | Where-Object { $_ -notin $columns })
    if ($missingColumns.Count -gt 0) {
        throw "The CopyLog is missing columns: $($missingColumns -join ', ')"
    }

    $destinationRoot = Get-DestinationRoot -Rows $rows
    $consoleText = ''
    $consoleIssue = 'No matching companion ConsoleLog is available.'
    if ($timingEnabled) {
        try {
            if ($null -ne $internalCopyLog) {
                $consoleName = [regex]::Replace($internalCopyLog.FullName.Replace('/', '\'), '(?i)_CopyLog\.csv$', '_ConsoleLog.txt')
                $consoleEntries = @($zipEntries | Where-Object {
                    $_.FullName.Replace('/', '\').Equals($consoleName, [StringComparison]::OrdinalIgnoreCase)
                })
                if ($consoleEntries.Count -gt 1) { throw 'Ambiguous companion ConsoleLog entries.' }
                if ($consoleEntries.Count -eq 1) {
                    $reader = [IO.StreamReader]::new($consoleEntries[0].Open())
                    try { $consoleText = $reader.ReadToEnd() }
                    finally { $reader.Dispose() }
                    $consoleIssue = ''
                }
            }
            else {
                $consolePath = [regex]::Replace($resolvedCopyLog, '(?i)_CopyLog\.csv$', '_ConsoleLog.txt')
                if ($consolePath -ne $resolvedCopyLog -and (Test-Path -LiteralPath $consolePath -PathType Leaf)) {
                    $consoleText = Get-Content -LiteralPath $consolePath -Raw
                    $consoleIssue = ''
                }
            }
        }
        catch { $consoleIssue = $_.Exception.Message }
    }
    Test-CopyLogTiming -Rows $rows -LogWriteUtc $logWriteUtc -ConsoleText $consoleText -ConsoleIssue $consoleIssue

    if ($isZip -and $null -eq $internalCopyLog) {
        $prefixes = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($row in $rows) {
            $mapped = Get-CollectionPath -Destination $row.DestinationFile -DestinationRoot $destinationRoot -CollectionRoot $collectionRoot
            $relative = [IO.Path]::GetRelativePath($collectionRoot, $mapped)
            foreach ($entry in $zipEntries) {
                $entryPath = $entry.FullName.Replace('/', '\')
                if ($entryPath.Equals($relative, [StringComparison]::OrdinalIgnoreCase)) {
                    [void]$prefixes.Add('')
                }
                elseif ($entryPath.EndsWith('\' + $relative, [StringComparison]::OrdinalIgnoreCase)) {
                    [void]$prefixes.Add($entryPath.Substring(0, $entryPath.Length - $relative.Length))
                }
            }
        }
        if ($prefixes.Count -ne 1) { throw 'Cannot infer one unambiguous ZIP collection root from the external CopyLog.' }
        $zipRootPrefix = @($prefixes)[0]
    }

    $expectedFiles = New-Object 'System.Collections.Generic.Dictionary[string,object]' (
        [StringComparer]::OrdinalIgnoreCase
    )

    for ($index = 0; $index -lt $rows.Count; $index++) {
        $row = $rows[$index]
        $rowNumber = $index + 2

        try {
            $expectedPath = Get-CollectionPath `
                -Destination ([string]$row.DestinationFile) `
                -DestinationRoot $destinationRoot `
                -CollectionRoot $collectionRoot
        }
        catch {
            Add-Finding -Type 'InvalidLogPath' `
                -Path ([string]$row.DestinationFile) `
                -Details "CSV row $rowNumber`: $($_.Exception.Message)"
            continue
        }

        if ($expectedFiles.ContainsKey($expectedPath)) {
            Add-Finding -Type 'DuplicateLogEntry' `
                -Path $expectedPath `
                -Details "More than one CopyLog row maps to this destination (including row $rowNumber)."
            continue
        }

        $expectedFiles.Add($expectedPath, [pscustomobject]@{
            Row       = $row
            RowNumber = $rowNumber
        })
    }

    if ($expectedFiles.Count -eq 0) { throw 'The CopyLog contains no usable mapped destinations.' }

    $allItems = New-Object 'System.Collections.Generic.List[object]'
    if ($isZip) {
        $archivePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $zipEntries) {
            $entryPath = $entry.FullName.Replace('/', '\')
            if ($entryPath.EndsWith('\')) { continue }
            if (-not $entryPath.StartsWith($zipRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "ZIP file is outside the selected collection root: $($entry.FullName)"
            }
            $relative = $entryPath.Substring($zipRootPrefix.Length)
            $rootPart = ($relative -split '\\', 2)[0]
            if ($relative.Contains('\') -and $rootPart -in @('System Volume Information', '$RECYCLE.BIN')) { continue }
            $item = Get-ZipItem -Entry $entry -RelativePath $relative
            if (-not $archivePaths.Add($item.FullName)) {
                Add-Finding -Type 'DuplicateArchiveEntry' -Path $item.FullName -Details 'Duplicate or Windows case-colliding ZIP file path.'
                continue
            }
            $allItems.Add($item)
        }
        $topLevelItems = @()
    }
    else { $topLevelItems = @(Get-ChildItem -LiteralPath $collectionRoot -Force) }
    foreach ($topLevelItem in $topLevelItems) {
        $isExcludedRootDirectory = (
            $topLevelItem.PSIsContainer -and
            (
                $topLevelItem.Name.Equals(
                    'System Volume Information',
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                $topLevelItem.Name.Equals(
                    '$RECYCLE.BIN',
                    [StringComparison]::OrdinalIgnoreCase
                )
            )
        )
        if ($isExcludedRootDirectory) {
            continue
        }

        $allItems.Add($topLevelItem)
        if ($topLevelItem.PSIsContainer) {
            foreach ($descendant in @(
                    Get-ChildItem -LiteralPath $topLevelItem.FullName -Recurse -Force
                )) {
                $allItems.Add($descendant)
            }
        }
    }

    foreach ($item in $allItems) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Add-Finding -Type 'ReparsePoint' `
                -Path $item.FullName `
                -Details 'Reparse points can redirect verification outside the mounted collection.'
        }
    }

    $actualFiles = New-Object 'System.Collections.Generic.Dictionary[string,object]' (
        [StringComparer]::OrdinalIgnoreCase
    )
    $longFileNamesDirectory = [IO.Path]::GetFullPath(
        (Join-Path $collectionRoot 'LongFileNames')
    ).TrimEnd('\')

    foreach ($item in $allItems) {
        if ($item.PSIsContainer) {
            continue
        }

        $parentPath = [IO.Path]::GetFullPath($item.DirectoryName).TrimEnd('\')
        $isSelectedCopyLog = $item.FullName.Equals(
            $resolvedCopyLog,
            [StringComparison]::OrdinalIgnoreCase
        )
        $isRootKapeLog = (
            $parentPath.Equals(
                $collectionRootForComparison,
                [StringComparison]::OrdinalIgnoreCase
            ) -and
            (
                $item.Name -like '*_CopyLog.csv' -or
                $item.Name -like '*_SkipLog.csv' -or
                $item.Name -like '*_SkipLog.csv.csv' -or
                $item.Name -like '*_ConsoleLog.txt'
            )
        )
        if ($isSelectedCopyLog -or $isRootKapeLog) {
            continue
        }

        $isOriginalPathSidecar = (
            $parentPath.Equals(
                $longFileNamesDirectory,
                [StringComparison]::OrdinalIgnoreCase
            ) -and
            $item.Name -match (
                '^(?<PayloadId>[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-' +
                '[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-' +
                '[0-9A-Fa-f]{12})_OriginalPathInfo\.txt$'
            ) -and
            -not $expectedFiles.ContainsKey($item.FullName)
        )
        if ($isOriginalPathSidecar) {
            $payloadId = $Matches['PayloadId']
            $payloadMatches = @(
                $expectedFiles.GetEnumerator() |
                    Where-Object {
                        [IO.Path]::GetDirectoryName($_.Key).Equals(
                            $longFileNamesDirectory,
                            [StringComparison]::OrdinalIgnoreCase
                        ) -and
                        [IO.Path]::GetFileNameWithoutExtension($_.Key).Equals(
                            $payloadId,
                            [StringComparison]::OrdinalIgnoreCase
                        )
                    }
            )

            if ($payloadMatches.Count -eq 1) {
                $sourcePath = (
                    [string]$payloadMatches[0].Value.Row.SourceFile
                ).Trim().Replace('/', '\')
                if ($sourcePath -match '^([A-Za-z]):\\(.+)$') {
                    $expectedOriginalPath = '{0}\{1}' -f $Matches[1], $Matches[2]
                    $recordedOriginalPath = (Read-EntryText -Item $item).Trim()
                    if ($recordedOriginalPath.Equals(
                            $expectedOriginalPath,
                            [StringComparison]::OrdinalIgnoreCase
                        )) {
                        continue
                    }

                    Add-Finding -Type 'InvalidOriginalPathInfo' `
                        -Path $item.FullName `
                        -Details (
                            "Sidecar path '$recordedOriginalPath' does not match " +
                            "CopyLog SourceFile '$sourcePath'."
                        )
                    continue
                }
            }
        }

        $actualFiles[$item.FullName] = $item
    }

    $verificationEnabled = (
        $VerifyMetadata -or
        $VerifyHashes -or
        $VerifyTimestamps
    )
    if ($VerifyMetadata) {
        $verificationActivity = 'Verifying file sizes, SHA-1 hashes, and timestamps'
    }
    elseif ($VerifyHashes -and $VerifyTimestamps) {
        $verificationActivity = 'Verifying SHA-1 hashes and timestamps'
    }
    elseif ($VerifyHashes) {
        $verificationActivity = 'Verifying SHA-1 hashes'
    }
    else {
        $verificationActivity = 'Verifying timestamps'
    }

    if ($verificationEnabled) {
        Write-Output "$verificationActivity..."
    }
    if ($VerifyMetadata -or $VerifyTimestamps) {
        if ($isZip) {
            Write-Output 'Creation timestamps: unavailable for direct ZIP verification.'
            Write-Output 'Modification timestamps: exact NTFS UTC when available; DOS requires explicit originating timezone.'
        }
        elseif ($ExtractedZip) {
            Write-Output 'Creation timestamps: skipped (-ExtractedZip).'
            if ($DosExtraction) { Write-Output 'Modification timestamps: explicit DOS two-second wall-clock policy.' }
            else { Write-Output 'Modification timestamps: exact UTC (no extraction tolerance).' }
        }
        else { Write-Output 'Creation and modification timestamps: exact UTC.' }
    }

    $processedFiles = 0
    foreach ($entry in $expectedFiles.GetEnumerator()) {
        if ($verificationEnabled) {
            $percentComplete = if ($expectedFiles.Count -eq 0) {
                100
            }
            else {
                [int](($processedFiles / $expectedFiles.Count) * 100)
            }
            Write-Progress `
                -Activity $verificationActivity `
                -Status (
                    "File {0} of {1}: {2}" -f
                    ($processedFiles + 1),
                    $expectedFiles.Count,
                    [IO.Path]::GetFileName($entry.Key)
                ) `
                -PercentComplete $percentComplete
        }

        $expectedPath = $entry.Key
        $logInfo = $entry.Value
        $row = $logInfo.Row

        if (-not $actualFiles.ContainsKey($expectedPath)) {
            Add-Finding -Type 'MissingFile' `
                -Path $expectedPath `
                -Details "Listed at CSV row $($logInfo.RowNumber) but not found in the collection."
            $processedFiles++
            continue
        }

        $actualItem = $actualFiles[$expectedPath]
        if ($VerifyMetadata) {
            [long]$loggedSize = 0
            $validSize = [long]::TryParse(
                ([string]$row.FileSize).Trim(),
                [Globalization.NumberStyles]::Integer,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$loggedSize
            )

            if (-not $validSize -or $loggedSize -lt 0) {
                Add-Finding -Type 'InvalidLoggedSize' `
                    -Path $expectedPath `
                    -Details "CSV row $($logInfo.RowNumber) has invalid FileSize '$($row.FileSize)'."
            }
            elseif ([long]$actualItem.Length -ne $loggedSize) {
                $sourcePath = ([string]$row.SourceFile).Trim().Replace('/', '\')
                $isUsnJournalDataStream = (
                    $sourcePath.EndsWith(
                        '\$Extend\$UsnJrnl:$J',
                        [StringComparison]::OrdinalIgnoreCase
                    ) -and
                    [IO.Path]::GetFileName($expectedPath).Equals(
                        '$J',
                        [StringComparison]::OrdinalIgnoreCase
                    )
                )
                if (-not $isUsnJournalDataStream) {
                    Add-Finding -Type 'SizeMismatch' `
                        -Path $expectedPath `
                        -Details "CopyLog: $loggedSize bytes; collection: $($actualItem.Length) bytes."
                }
            }
        }

        if ($VerifyMetadata -or $VerifyTimestamps) {
            $sourceFileName = [IO.Path]::GetFileName(
                ([string]$row.SourceFile).Trim().Replace('/', '\')
            )
            $skipTimestampComparison = (
                $sourceFileName.Equals(
                    '$Boot',
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                $sourceFileName.Equals(
                    '$LogFile',
                    [StringComparison]::OrdinalIgnoreCase
                )
            )
            if (-not $skipTimestampComparison) {
                if (-not $isZip -and -not $ExtractedZip) {
                    Test-LoggedTimestamp `
                        -Field 'CreatedOnUtc' `
                        -LoggedValue ([string]$row.CreatedOnUtc) `
                        -ActualValueUtc $actualItem.CreationTimeUtc `
                        -Path $expectedPath `
                        -RowNumber $logInfo.RowNumber
                }
                $useDos = $DosExtraction -or ($isZip -and -not $actualItem.UtcAvailable -and $null -ne $zipTimeZone)
                if ($isZip -and -not $actualItem.UtcAvailable -and -not $useDos) {
                    [void]$timestampLimitations.Add('Some ZIP modification checks unavailable: no validated UTC metadata or explicit -ZipTimeZoneId.')
                }
                else {
                    $modifiedTime = if ($isZip -and $useDos) { $actualItem.ZipEntry.LastWriteTime.DateTime }
                        elseif ($DosExtraction) { $actualItem.LastWriteTime }
                        else { $actualItem.LastWriteTimeUtc }
                    Test-LoggedTimestamp `
                        -Field 'ModifiedOnUtc' `
                        -LoggedValue ([string]$row.ModifiedOnUtc) `
                        -ActualValueUtc $modifiedTime `
                        -Path $expectedPath `
                        -RowNumber $logInfo.RowNumber `
                        -DosWallClock:$useDos
                }
            }
        }

        if ($VerifyMetadata -or $VerifyHashes) {
            $loggedHash = ([string]$row.SourceFileSha1).Trim()
            if ($loggedHash -notmatch '^[A-Fa-f0-9]{40}$') {
                Add-Finding -Type 'InvalidLoggedSha1' `
                    -Path $expectedPath `
                    -Details "CSV row $($logInfo.RowNumber) has no valid SHA-1 value."
            }
            elseif (($actualItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                try {
                    $actualHash = Get-EntryHash -Item $actualItem
                    if (-not $actualHash.Equals(
                            $loggedHash,
                            [StringComparison]::OrdinalIgnoreCase
                        )) {
                        Add-Finding -Type 'Sha1Mismatch' `
                            -Path $expectedPath `
                            -Details "CopyLog: $loggedHash; collection: $actualHash."
                    }
                }
                catch {
                    $readFailure = $_.Exception.GetBaseException()
                    if ($isZip -and ($readFailure -is [NotSupportedException] -or $readFailure -is [IO.InvalidDataException])) {
                        throw
                    }
                    Add-Finding -Type 'HashReadError' `
                        -Path $expectedPath `
                        -Details $_.Exception.Message
                }
            }
        }

        $processedFiles++
    }

    if ($verificationEnabled) {
        Write-Progress -Activity $verificationActivity -Completed
        Write-Output "$verificationActivity complete."
    }

    foreach ($entry in $actualFiles.GetEnumerator()) {
        if (-not $expectedFiles.ContainsKey($entry.Key)) {
            Add-Finding -Type 'UnloggedFile' `
                -Path $entry.Key `
                -Details 'Present in the collection but absent from the CopyLog.'
        }
    }

    Write-Output ''
    foreach ($limitation in $timestampLimitations) { Write-Warning $limitation }
    Write-Output 'KAPE collection verification'
    if ($isZip) { Write-Output "  ZIP:               $resolvedZip (streamed, not extracted)" }
    Write-Output "  Directory:         $collectionRoot"
    Write-Output "  CopyLog:           $resolvedCopyLog"
    Write-Output "  KAPE target root:  $destinationRoot"
    Write-Output "  CopyLog rows:      $($rows.Count)"
    Write-Output "  Logged paths:      $($expectedFiles.Count)"
    Write-Output "  Collected files:   $($actualFiles.Count)"
    Write-Output "  Size verification: $($VerifyMetadata.IsPresent)"
    Write-Output "  Hash verification: $($VerifyMetadata.IsPresent -or $VerifyHashes.IsPresent)"
    Write-Output "  Timestamp check:   $($VerifyMetadata.IsPresent -or $VerifyTimestamps.IsPresent)"
    Write-Output ''

    if ($findings.Count -eq 0) {
        Write-Output 'PASS: The CopyLog and collected file structure are consistent.'
        if ($VerifyMetadata -or $VerifyHashes) {
            Write-Output 'PASS: Every logged SHA-1 hash matches its collected file.'
        }
        exit 0
    }

    Write-Output "FAIL: $($findings.Count) integrity finding(s) detected."
    Write-Output ''
    $findings |
        Sort-Object Type, Path |
        Format-Table -AutoSize -Wrap Type, Path, Details |
        Out-String -Width 4096 |
        Write-Output
    exit 1
}
catch {
    Write-Error "Verification could not be completed: $($_.Exception.Message)" -ErrorAction Continue
    exit 2
}
finally {
    if ($null -ne $zipMetadataStream) { $zipMetadataStream.Dispose() }
    if ($null -ne $archive) { $archive.Dispose() }
}
