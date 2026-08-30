<#
.SYNOPSIS
Verifies a mounted KAPE collection against its CopyLog.

.DESCRIPTION
Checks both directions: every CopyLog entry must exist with the recorded size,
and every file below the collection directory must have a CopyLog entry.
CopyLog and SkipLog files located directly in the collection directory are
excluded from the collected-file inventory. Its System Volume Information and
$RECYCLE.BIN directories are also excluded because they belong to the mounted
volume rather than the collection.

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

.PARAMETER VerifyMetadata
Verifies file sizes, SHA-1 hashes, and filesystem timestamps.

.PARAMETER VerifyHashes
Calculates SHA-1 for every logged file and compares it with SourceFileSha1.

.PARAMETER VerifyTimestamps
Compares each file's creation and modification UTC timestamps with CreatedOnUtc
and ModifiedOnUtc in the CopyLog. LastAccessedOnUtc is intentionally ignored,
as are timestamps for the NTFS $Boot and $LogFile metadata files.

.EXAMPLE
.\Test-KapeCollection.ps1 -d D:\

.EXAMPLE
.\Test-KapeCollection.ps1 -d C:\temp\t -VerifyMetadata

.NOTES
Exit code 0 means the collection is consistent, 1 means integrity findings
were detected, and 2 means verification could not be completed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Alias('d')]
    [ValidateNotNullOrEmpty()]
    [string]$Directory,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CopyLogPath,

    [Parameter()]
    [switch]$VerifyMetadata,

    [Parameter()]
    [switch]$VerifyHashes,

    [Parameter()]
    [switch]$VerifyTimestamps
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

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
        [int]$RowNumber
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

    $actualTimestamp = $ActualValueUtc.ToUniversalTime()
    if ($loggedTimestamp.UtcDateTime.Ticks -ne $actualTimestamp.Ticks) {
        Add-Finding -Type 'TimestampMismatch' `
            -Path $Path `
            -Details (
                "$Field - CopyLog: " +
                "$($loggedTimestamp.UtcDateTime.ToString('o')); collection: " +
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
    $resolvedMount = (Resolve-Path -LiteralPath $Directory).ProviderPath
    $mountItem = Get-Item -LiteralPath $resolvedMount -Force
    if (-not $mountItem.PSIsContainer) {
        throw "Directory is not a directory: $Directory"
    }
    $collectionRoot = [IO.Path]::GetFullPath($resolvedMount)
    $collectionRootForComparison = $collectionRoot.TrimEnd('\')

    if ($PSBoundParameters.ContainsKey('CopyLogPath')) {
        $resolvedCopyLog = (Resolve-Path -LiteralPath $CopyLogPath).ProviderPath
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

    $copyLogItem = Get-Item -LiteralPath $resolvedCopyLog -Force
    if ($copyLogItem.PSIsContainer) {
        throw "CopyLogPath is not a file: $resolvedCopyLog"
    }

    $rows = @(Import-Csv -LiteralPath $resolvedCopyLog)
    if ($rows.Count -eq 0) {
        throw "The CopyLog contains no data rows: $resolvedCopyLog"
    }

    $columns = @($rows[0].PSObject.Properties.Name)
    $missingColumns = @($requiredColumns | Where-Object { $_ -notin $columns })
    if ($missingColumns.Count -gt 0) {
        throw "The CopyLog is missing columns: $($missingColumns -join ', ')"
    }

    $destinationRoot = Get-DestinationRoot -Rows $rows

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

    $allItems = New-Object 'System.Collections.Generic.List[System.IO.FileSystemInfo]'
    $topLevelItems = @(Get-ChildItem -LiteralPath $collectionRoot -Force)
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
                $item.Name -like '*_SkipLog.csv.csv'
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
                    $recordedOriginalPath = (
                        Get-Content -LiteralPath $item.FullName -Raw
                    ).Trim()
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
                Test-LoggedTimestamp `
                    -Field 'CreatedOnUtc' `
                    -LoggedValue ([string]$row.CreatedOnUtc) `
                    -ActualValueUtc $actualItem.CreationTimeUtc `
                    -Path $expectedPath `
                    -RowNumber $logInfo.RowNumber
                Test-LoggedTimestamp `
                    -Field 'ModifiedOnUtc' `
                    -LoggedValue ([string]$row.ModifiedOnUtc) `
                    -ActualValueUtc $actualItem.LastWriteTimeUtc `
                    -Path $expectedPath `
                    -RowNumber $logInfo.RowNumber
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
                    $actualHash = (Get-FileHash -LiteralPath $expectedPath -Algorithm SHA1).Hash
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
    Write-Output 'KAPE collection verification'
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
    Write-Error "Verification could not be completed: $($_.Exception.Message)"
    exit 2
}
