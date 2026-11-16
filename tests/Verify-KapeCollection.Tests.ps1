#requires -Version 7.0
param(
    [string]$TestRoot = (Join-Path ([IO.Path]::GetTempPath()) ('KapeVerifier-' + [guid]::NewGuid())),
    [string]$CaseFilter = '*'
)
$ErrorActionPreference = 'Stop'
$verifier = Join-Path $PSScriptRoot '..\Verify-KapeCollection.ps1'
if (Test-Path -LiteralPath $TestRoot) { throw 'TestRoot must not already exist.' }
[IO.Directory]::CreateDirectory($TestRoot) | Out-Null
Copy-Item -LiteralPath $verifier -Destination (Join-Path $TestRoot 'verifier-tested.ps1')
$verifier = Join-Path $TestRoot 'verifier-tested.ps1'
Get-FileHash -LiteralPath $verifier -Algorithm SHA256 |
    Select-Object Algorithm,Hash | ConvertTo-Json | Set-Content (Join-Path $TestRoot 'verifier-hash.json')
$results = [Collections.Generic.List[object]]::new()
$created = [datetime]'2026-01-02T03:04:05.1234567Z'
$modified = [datetime]'2026-02-03T04:05:07.7654321Z'
$modes = [ordered]@{
    inventory = @()
    hashes = @('-VerifyHashes')
    timestamps = @('-VerifyTimestamps')
    combined = @('-VerifyHashes', '-VerifyTimestamps')
    metadata = @('-VerifyMetadata')
}

function New-Fixture([string]$Name) {
    $root = Join-Path $TestRoot $Name
    [IO.Directory]::CreateDirectory("$root\C\fixture\nested") | Out-Null
    $files = [ordered]@{
        'C\fixture\ordinary.txt' = [Text.Encoding]::UTF8.GetBytes('unchanged ordinary data')
        'C\fixture\empty.txt' = [byte[]]@()
        'C\fixture\nested\binary.bin' = [byte[]](0..255)
        'C\fixture\hidden.txt' = [Text.Encoding]::UTF8.GetBytes('hidden')
    }
    $rows = foreach ($entry in $files.GetEnumerator()) {
        $path = Join-Path $root $entry.Key
        [IO.File]::WriteAllBytes($path, $entry.Value)
        [IO.File]::SetCreationTimeUtc($path, $created)
        [IO.File]::SetLastWriteTimeUtc($path, $modified)
        [pscustomobject][ordered]@{
            CopiedTimestamp = '2026-04-05 06:07:08.1234567'
            SourceFile = $entry.Key.Insert(1, ':')
            DestinationFile = 'G:\acquisition\' + $entry.Key
            FileSize = $entry.Value.Length
            SourceFileSha1 = (Get-FileHash -LiteralPath $path -Algorithm SHA1).Hash.ToLowerInvariant()
            DeferredCopy = 'False'
            CreatedOnUtc = $created.ToString('o')
            ModifiedOnUtc = $modified.ToString('o')
            LastAccessedOnUtc = $modified.ToString('o')
            CopyDuration = '00:00:00.001'
        }
    }
    [IO.File]::SetAttributes("$root\C\fixture\hidden.txt", [IO.FileAttributes]::Hidden)
    $rows | Export-Csv "$root\test_CopyLog.csv" -NoTypeInformation
    [IO.File]::SetLastWriteTimeUtc("$root\test_CopyLog.csv", [datetime]'2026-04-05T06:07:08.124Z')
    return $root
}

function Invoke-Check([string]$Name, [string[]]$Arguments, [int]$Exit, [string[]]$Contains = @(), [string[]]$Absent = @()) {
    if ($Name -notlike $CaseFilter) { return }
    $start = [Diagnostics.ProcessStartInfo]::new((Get-Command pwsh).Source)
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in (@('-NoProfile','-File',$verifier) + $Arguments)) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($start)
    $outTask = $process.StandardOutput.ReadToEndAsync()
    $errTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdout = $outTask.GetAwaiter().GetResult()
    $stderr = $errTask.GetAwaiter().GetResult()
    $passed = $process.ExitCode -eq $Exit
    foreach ($text in $Contains) { $passed = $passed -and ($stdout + $stderr).Contains($text, [StringComparison]::OrdinalIgnoreCase) }
    foreach ($text in $Absent) { $passed = $passed -and -not ($stdout + $stderr).Contains($text, [StringComparison]::OrdinalIgnoreCase) }
    $results.Add([pscustomobject]@{
        Name=$Name; Passed=$passed; ExpectedExit=$Exit; ActualExit=$process.ExitCode
        Arguments=$Arguments; Stdout=$stdout; Stderr=$stderr
    })
    $results | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $TestRoot 'results.json')
    $process.Dispose()
    if (-not $passed) { Write-Warning "FAILED: $Name (expected $Exit): $stdout $stderr" }
}

function New-TestZip([string]$Root, [string]$Name, [string]$Prefix = '', [string[]]$ExtraNames = @()) {
    $path = Join-Path $TestRoot "$Name.zip"
    $zip = [IO.Compression.ZipFile]::Open($path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in Get-ChildItem -LiteralPath $Root -File -Recurse -Force) {
            $relative = [IO.Path]::GetRelativePath($Root, $file.FullName).Replace('\', '/')
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file.FullName, $Prefix + $relative) | Out-Null
        }
        foreach ($name in $ExtraNames) {
            $entry = $zip.CreateEntry($name)
            $writer = [IO.StreamWriter]::new($entry.Open())
            try { $writer.Write('extra') } finally { $writer.Dispose() }
        }
    }
    finally { $zip.Dispose() }
    return $path
}

function Add-NtfsTimes([string]$ZipPath, [string]$Root, [switch]$Malformed) {
    $bytes = [IO.File]::ReadAllBytes($ZipPath)
    $end = $bytes.Length - 22
    $offset = [BitConverter]::ToUInt32($bytes, $end + 16)
    $count = [BitConverter]::ToUInt16($bytes, $end + 10)
    $memory = [IO.MemoryStream]::new()
    $writer = [IO.BinaryWriter]::new($memory)
    try {
        $writer.Write($bytes, 0, [int]$offset)
        $position = [int]$offset
        for ($index = 0; $index -lt $count; $index++) {
            $header = $bytes[$position..($position + 45)]
            $nameLength = [BitConverter]::ToUInt16($header,28)
            $extraLength = [BitConverter]::ToUInt16($header,30)
            $commentLength = [BitConverter]::ToUInt16($header,32)
            $name = [Text.Encoding]::UTF8.GetString($bytes, $position + 46, $nameLength)
            $file = Get-Item -LiteralPath (Join-Path $Root $name.Replace('/','\')) -Force
            [BitConverter]::GetBytes([uint16]($extraLength + 36)).CopyTo($header,30)
            $writer.Write([byte[]]$header)
            $writer.Write($bytes, $position + 46, $nameLength + $extraLength)
            $writer.Write([uint16]10)
            $writer.Write([uint16]32)
            $writer.Write([uint32]0)
            $writer.Write([uint16]1)
            $writer.Write([uint16]$(if ($Malformed) { 23 } else { 24 }))
            $writer.Write([long]$file.LastWriteTimeUtc.ToFileTimeUtc())
            $writer.Write([long]$file.LastAccessTimeUtc.ToFileTimeUtc())
            $writer.Write([long]$file.CreationTimeUtc.ToFileTimeUtc())
            $writer.Write($bytes, $position + 46 + $nameLength + $extraLength, $commentLength)
            $position += 46 + $nameLength + $extraLength + $commentLength
        }
        $directorySize = $memory.Position - $offset
        $tail = $bytes[$end..($bytes.Length-1)]
        [BitConverter]::GetBytes([uint32]$directorySize).CopyTo($tail,12)
        $writer.Write([byte[]]$tail)
        [IO.File]::WriteAllBytes($ZipPath, $memory.ToArray())
    }
    finally { $writer.Dispose(); $memory.Dispose() }
}

function ConvertTo-TestZip64([string]$ZipPath) {
    $bytes = [IO.File]::ReadAllBytes($ZipPath)
    $end = $bytes.Length - 22
    $offset = [BitConverter]::ToUInt32($bytes, $end + 16)
    $size = [BitConverter]::ToUInt32($bytes, $end + 12)
    $count = [BitConverter]::ToUInt16($bytes, $end + 10)
    $memory = [IO.MemoryStream]::new()
    $writer = [IO.BinaryWriter]::new($memory)
    try {
        $writer.Write($bytes,0,$end)
        $writer.Write([uint32]0x06064b50)
        $writer.Write([long]44)
        $writer.Write([uint16]45)
        $writer.Write([uint16]45)
        $writer.Write([uint32]0)
        $writer.Write([uint32]0)
        $writer.Write([long]$count)
        $writer.Write([long]$count)
        $writer.Write([long]$size)
        $writer.Write([long]$offset)
        $writer.Write([uint32]0x07064b50)
        $writer.Write([uint32]0)
        $writer.Write([long]$end)
        $writer.Write([uint32]1)
        $tail = $bytes[$end..($bytes.Length-1)]
        [BitConverter]::GetBytes([uint16]::MaxValue).CopyTo($tail,8)
        [BitConverter]::GetBytes([uint16]::MaxValue).CopyTo($tail,10)
        [BitConverter]::GetBytes([uint32]::MaxValue).CopyTo($tail,12)
        [BitConverter]::GetBytes([uint32]::MaxValue).CopyTo($tail,16)
        $writer.Write([byte[]]$tail)
        [IO.File]::WriteAllBytes($ZipPath,$memory.ToArray())
    }
    finally { $writer.Dispose(); $memory.Dispose() }
}

foreach ($case in @('clean','add','delete','rename','resize','same-size','creation','modified','combined')) {
    $root = New-Fixture $case
    $payload = "$root\C\fixture\ordinary.txt"
    switch ($case) {
        'add' { [IO.File]::WriteAllText("$root\C\fixture\nested\added.txt", 'added') }
        'delete' { [IO.File]::Delete($payload) }
        'rename' { [IO.File]::Move($payload, "$payload.renamed") }
        'resize' { [IO.File]::AppendAllText($payload, 'more') }
        { $_ -in 'same-size','combined' } {
            $bytes = [IO.File]::ReadAllBytes($payload)
            $bytes[0] = $bytes[0] -bxor 1
            [IO.File]::WriteAllBytes($payload, $bytes)
            if ($case -eq 'combined') {
                [IO.File]::WriteAllText("$root\C\fixture\nested\added.txt", 'added')
                [IO.File]::Delete("$root\C\fixture\empty.txt")
            }
        }
        'creation' { [IO.File]::SetCreationTimeUtc($payload, $created.AddHours(1)) }
        'modified' { [IO.File]::SetLastWriteTimeUtc($payload, $modified.AddHours(1)) }
    }
    if ($case -in @('resize','same-size','combined')) {
        [IO.File]::SetCreationTimeUtc($payload, $created)
        [IO.File]::SetLastWriteTimeUtc($payload, $modified)
        $row = Import-Csv "$root\test_CopyLog.csv" | Where-Object SourceFile -like '*ordinary.txt'
        if ((Get-FileHash -LiteralPath $payload -Algorithm SHA1).Hash -eq $row.SourceFileSha1) {
            throw 'Mutation did not change independently calculated SHA1.'
        }
        if ($case -ne 'resize' -and (Get-Item $payload).Length -ne $row.FileSize) { throw 'Same-size mutation resized file.' }
    }
    $zip = New-TestZip $root $case
    Add-NtfsTimes $zip $root
    $extract = Join-Path $TestRoot "$case-extracted"
    [IO.Compression.ZipFile]::ExtractToDirectory($zip, $extract)
    foreach ($mode in $modes.GetEnumerator()) {
        $hashes = $mode.Key -in 'hashes','combined','metadata'
        $times = $mode.Key -in 'timestamps','combined','metadata'
        $expected = @()
        if ($case -in 'add','combined') { $expected += 'UnloggedFile','added.txt' }
        if ($case -in 'delete','rename','combined') { $expected += 'MissingFile' }
        if ($case -eq 'rename') { $expected += 'UnloggedFile','ordinary.txt.renamed' }
        if ($hashes -and $case -in 'resize','same-size','combined') { $expected += 'Sha1Mismatch','ordinary.txt' }
        if ($mode.Key -eq 'metadata' -and $case -eq 'resize') { $expected += 'SizeMismatch' }
        $directoryExpected = @($expected)
        if ($times -and $case -in 'creation','modified') { $directoryExpected += 'TimestampMismatch','ordinary.txt' }
        $exit = [int]($directoryExpected.Count -gt 0)
        Invoke-Check "$case-directory-$($mode.Key)" (@('-d',$root) + $mode.Value) $exit $directoryExpected
        $zipExpected = @($expected)
        if ($times -and $case -eq 'modified') { $zipExpected += 'TimestampMismatch','ordinary.txt' }
        $zipExit = [int]($zipExpected.Count -gt 0)
        Invoke-Check "$case-zip-$($mode.Key)" (@('-ZipPath',$zip) + $mode.Value) $zipExit $zipExpected
        Invoke-Check "$case-extracted-$($mode.Key)" (@('-d',$extract,'-ExtractedZip','-DosExtraction','-ZipTimeZoneId','UTC') + $mode.Value) $zipExit $zipExpected
    }
}

$clean = New-Fixture 'special-clean'
$dosZip = New-TestZip $clean 'dos'
Invoke-Check 'dos-without-zone' @('-ZipPath',$dosZip,'-VerifyMetadata') 0 @('Some ZIP modification checks unavailable')
Invoke-Check 'dos-explicit-zone' @('-ZipPath',$dosZip,'-VerifyMetadata','-ZipTimeZoneId','UTC') 0
$ntfsZip = New-TestZip $clean 'ntfs'
Add-NtfsTimes $ntfsZip $clean
Invoke-Check 'ntfs-exact-utc' @('-ZipPath',$ntfsZip,'-VerifyMetadata') 0 @('Creation timestamps: unavailable') @('TimestampMismatch')
$malformed = New-TestZip $clean 'malformed-extra'
Add-NtfsTimes $malformed $clean -Malformed
Invoke-Check 'malformed-optional-extra' @('-ZipPath',$malformed,'-VerifyMetadata') 0 @('ZIP UTC timestamp metadata unavailable','Some ZIP modification checks unavailable')
$wrapped = New-TestZip $clean 'wrapped' 'enclosing/'
Invoke-Check 'wrapped-root' @('-ZipPath',$wrapped,'-VerifyHashes') 0
Invoke-Check 'external-log-wrapped' @('-ZipPath',$wrapped,'-CopyLogPath',"$clean\test_CopyLog.csv",'-VerifyHashes') 0
$duplicate = New-TestZip $clean 'duplicate' '' @('C/fixture/ordinary.txt')
Invoke-Check 'duplicate-zip-path' @('-ZipPath',$duplicate,'-VerifyHashes') 1 @('DuplicateArchiveEntry')
$collision = New-TestZip $clean 'case-collision' '' @('C/fixture/ORDINARY.TXT')
Invoke-Check 'case-colliding-zip-path' @('-ZipPath',$collision,'-VerifyHashes') 1 @('DuplicateArchiveEntry')
foreach ($name in @('../escape','/absolute','C:/drive','C\fixture\..\escape','C/fixture/trailing.')) {
    $unsafe = New-TestZip $clean ('unsafe-' + [guid]::NewGuid().ToString('N')) '' @($name)
    Invoke-Check "unsafe-$name" @('-ZipPath',$unsafe,'-VerifyHashes') 2 @('Unsafe ZIP entry') @('PASS:','Verifying SHA-1')
}
$corrupt = Join-Path $TestRoot 'corrupt.zip'
[IO.File]::WriteAllText($corrupt,'not a zip')
Invoke-Check 'corrupt-zip' @('-ZipPath',$corrupt) 2 @('Verification could not be completed') @('PASS:')

foreach ($case in @('missing','empty','columns','ambiguous','uninferrable')) {
    $root = New-Fixture "log-$case"
    $log = "$root\test_CopyLog.csv"
    switch ($case) {
        'missing' { [IO.File]::Delete($log) }
        'empty' { [IO.File]::WriteAllText($log,'') }
        'columns' { [IO.File]::WriteAllText($log,"SourceFile,DestinationFile`r`nC:\a,G:\t\C\a") }
        'ambiguous' { [IO.File]::Copy($log,"$root\second_CopyLog.csv") }
        'uninferrable' {
            $rows = @(Import-Csv $log)
            foreach ($row in $rows) { $row.SourceFile='not-an-absolute-source' }
            $rows | Export-Csv $log -NoTypeInformation
        }
    }
    Invoke-Check "preflight-$case-directory" @('-d',$root,'-VerifyMetadata') 2 @('Verification could not be completed') @('PASS:','Verifying file sizes')
    $zip = New-TestZip $root "log-$case"
    Invoke-Check "preflight-$case-zip" @('-ZipPath',$zip,'-VerifyMetadata') 2 @('Verification could not be completed') @('PASS:','Verifying file sizes')
}
Invoke-Check 'explicit-missing-log' @('-d',$clean,'-CopyLogPath',"$TestRoot\missing.csv") 2 @('Verification could not be completed') @('PASS:')
Invoke-Check 'bad-dos-switches' @('-d',$clean,'-DosExtraction') 2 @('-DosExtraction requires')
Invoke-Check 'extracted-not-with-zip' @('-ZipPath',$dosZip,'-ExtractedZip') 1 @('parameter set')

$locked = [IO.File]::Open("$clean\C\fixture\ordinary.txt",[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try { Invoke-Check 'locked-payload' @('-d',$clean,'-VerifyHashes') 1 @('HashReadError') }
finally { $locked.Dispose() }
$lockedLog = [IO.File]::Open("$clean\test_CopyLog.csv",[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try { Invoke-Check 'locked-copylog' @('-d',$clean,'-VerifyHashes') 2 @('Verification could not be completed') @('PASS:','Verifying SHA-1') }
finally { $lockedLog.Dispose() }

foreach ($case in @('normal','late','early','reordered','invalid','offset','dst-ambiguous','dst-invalid')) {
    $root = New-Fixture "timing-$case"
    $log = "$root\test_CopyLog.csv"
    $rows = @(Import-Csv $log)
    $zone = 'UTC'
    switch ($case) {
        'late' { [IO.File]::SetLastWriteTimeUtc($log,[datetime]'2026-04-05T07:07:08Z') }
        'early' { [IO.File]::SetLastWriteTimeUtc($log,[datetime]'2026-04-05T05:07:08Z') }
        'reordered' {
            $rows[0].CopiedTimestamp = '2026-04-05 06:07:10.123'
            $rows[-1].CopiedTimestamp = '2026-04-05 06:00:00.000'
            $rows | Export-Csv $log -NoTypeInformation
            [IO.File]::SetLastWriteTimeUtc($log,[datetime]'2026-04-05T06:07:10.124Z')
        }
        'invalid' {
            $rows[0].CopiedTimestamp = 'invalid'
            $rows | Export-Csv $log -NoTypeInformation
        }
        'offset' {
            foreach ($row in $rows) { $row.CopiedTimestamp = '2026-04-05T01:07:08.1234567-05:00' }
            $rows | Export-Csv $log -NoTypeInformation
            [IO.File]::SetLastWriteTimeUtc($log,[datetime]'2026-04-05T06:07:08.124Z')
        }
        { $_ -in 'dst-ambiguous','dst-invalid' } {
            $zone='Eastern Standard Time'
            $rows[0].CopiedTimestamp = if ($case -eq 'dst-ambiguous') { '2026-11-01 01:30:00' } else { '2026-03-08 02:30:00' }
            $rows | Export-Csv $log -NoTypeInformation
        }
    }
    $text = if ($case -in 'late','early') { 'CopyLog timing is suspicious' }
        elseif ($case -in 'invalid','dst-ambiguous','dst-invalid') { 'CopyLog timing inconclusive' }
        else { 'within the supplied allowance' }
    Invoke-Check "timing-$case" @('-d',$root,'-VerifyMetadata','-CopyLogTimingAllowanceSeconds','2','-CollectionTimeZoneId',$zone) 0 @($text,'PASS:')
}
Invoke-Check 'timing-no-zone' @('-d',$clean,'-CopyLogTimingAllowanceSeconds','2') 0 @('Offsetless copy events require')
Invoke-Check 'timing-zero-allowance' @('-d',$clean,'-CopyLogTimingAllowanceSeconds','0','-CollectionTimeZoneId','UTC') 0 @('CopyLog timing is suspicious')
Invoke-Check 'timing-offset-no-zone' @('-d',"$TestRoot\timing-offset",'-CopyLogTimingAllowanceSeconds','2') 0 @('within the supplied allowance')

$zip64 = New-TestZip $clean 'zip64'
ConvertTo-TestZip64 $zip64
Invoke-Check 'extended-zip64-payloads' @('-ZipPath',$zip64,'-VerifyMetadata') 0 @('ZIP64 UTC timestamp metadata is not decoded','Some ZIP modification checks unavailable','Every logged SHA-1')
Invoke-Check 'extended-ntfs-independent-zone' @('-ZipPath',$ntfsZip,'-VerifyMetadata','-ZipTimeZoneId','Eastern Standard Time') 0 @('Every logged SHA-1') @('TimestampMismatch')
Invoke-Check 'extended-extracted-strict-modification' @('-d',"$TestRoot\clean-extracted",'-ExtractedZip','-VerifyMetadata') 1 @('TimestampMismatch','ModifiedOnUtc') @('CreatedOnUtc - CopyLog')
Invoke-Check 'extended-extracted-creation-only' @('-d',"$TestRoot\creation",'-ExtractedZip','-VerifyMetadata') 0 @('Creation timestamps: skipped')
foreach ($case in @('non-utc','ambiguous','nonexistent')) {
    $root = New-Fixture "dos-$case"
    $log = "$root\test_CopyLog.csv"
    $rows = @(Import-Csv $log)
    $zone = [TimeZoneInfo]::FindSystemTimeZoneById('Eastern Standard Time')
    if ($case -eq 'ambiguous') {
        foreach ($row in $rows) { $row.ModifiedOnUtc = '2026-11-01T05:30:01Z' }
        $rows | Export-Csv $log -NoTypeInformation
    }
    $zip = New-TestZip $root "dos-$case"
    $archive = [IO.Compression.ZipFile]::Open($zip,[IO.Compression.ZipArchiveMode]::Update)
    try {
        foreach ($entry in $archive.Entries) {
            if ($entry.Name -like '*_CopyLog.csv') { continue }
            $time = if ($case -eq 'ambiguous') { [datetime]'2026-11-01T05:30:01Z' } else { $modified }
            $wall = [TimeZoneInfo]::ConvertTimeFromUtc([datetime]::SpecifyKind($time,[DateTimeKind]::Utc),$zone)
            if ($case -eq 'nonexistent') { $wall = [datetime]'2026-03-08T02:30:00' }
            $entry.LastWriteTime = [DateTimeOffset]::new([datetime]::SpecifyKind($wall,[DateTimeKind]::Unspecified),[TimeSpan]::Zero)
        }
    }
    finally { $archive.Dispose() }
    $text = if ($case -eq 'non-utc') { 'Every logged SHA-1' } else { 'ambiguous/invalid timezone interval' }
    Invoke-Check "extended-dos-$case" @('-ZipPath',$zip,'-VerifyMetadata','-ZipTimeZoneId','Eastern Standard Time') 0 @($text) @('TimestampMismatch')
}

$special = New-Fixture 'kape-special'
$guid = '3b6e1606-b4e0-4b8f-a4cb-87ee6e247de9'
$longSource = 'C:\fixture\' + ('long-segment\' * 24) + 'long.bin'
$longRelative = 'C\fixture\' + ('long-segment\' * 24) + 'long.bin'
$specialFiles = @(
    @{Relative="LongFileNames\$guid.bin";Source=$longSource;Size=3},
    @{Relative=$longRelative;Source=$longSource;Size=3},
    @{Relative='C\$Boot';Source='C:\$Boot';Size=3},
    @{Relative='C\$LogFile';Source='C:\$LogFile';Size=3},
    @{Relative='C\$Extend\$J';Source='C:\$Extend\$UsnJrnl:$J';Size=0}
)
$rows = @(Import-Csv "$special\test_CopyLog.csv")
foreach ($definition in $specialFiles) {
    $path = Join-Path $special $definition.Relative
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) | Out-Null
    [IO.File]::WriteAllBytes($path,[byte[]]@(1,2,3))
    [IO.File]::SetCreationTimeUtc($path,$created)
    [IO.File]::SetLastWriteTimeUtc($path,$modified)
    $row = $rows[0].PSObject.Copy()
    $row.SourceFile=$definition.Source
    $row.DestinationFile='G:\acquisition\' + $definition.Relative
    $row.FileSize=[string]$definition.Size
    $row.SourceFileSha1=(Get-FileHash -LiteralPath $path -Algorithm SHA1).Hash
    $rows += $row
}
$rows | Export-Csv "$special\test_CopyLog.csv" -NoTypeInformation
$sidecar = "$special\LongFileNames\${guid}_OriginalPathInfo.txt"
[IO.File]::WriteAllText($sidecar,$longSource.Replace(':',''))
foreach ($name in @('$Boot','$LogFile')) { [IO.File]::SetLastWriteTimeUtc("$special\C\$name",$modified.AddHours(1)) }
[IO.Directory]::CreateDirectory("$special\System Volume Information") | Out-Null
[IO.File]::WriteAllText("$special\System Volume Information\ignored.txt",'ignored')
[IO.File]::WriteAllText("$special\metadata_SkipLog.csv.csv",'ignored')
Invoke-Check 'extended-kape-special-directory' @('-d',$special,'-VerifyMetadata') 0 @('Every logged SHA-1')
$specialZip = New-TestZip $special 'kape-special'
Add-NtfsTimes $specialZip $special
Invoke-Check 'extended-kape-special-zip' @('-ZipPath',$specialZip,'-VerifyMetadata') 0 @('Every logged SHA-1')
[IO.File]::WriteAllText($sidecar,'wrong source path')
Invoke-Check 'extended-altered-sidecar' @('-d',$special,'-VerifyHashes') 1 @('InvalidOriginalPathInfo')
[IO.File]::Delete($sidecar)
Invoke-Check 'extended-known-deleted-sidecar-limitation' @('-d',$special,'-VerifyHashes') 0
[IO.File]::WriteAllText("$special\LongFileNames\11111111-1111-1111-1111-111111111111_OriginalPathInfo.txt",'orphan')
Invoke-Check 'extended-orphan-sidecar' @('-d',$special) 1 @('UnloggedFile')
$payload = Join-Path $special $longRelative
$bytes = [IO.File]::ReadAllBytes($payload)
$bytes[0] = 4
[IO.File]::WriteAllBytes($payload,$bytes)
Invoke-Check 'extended-long-path-hash' @('-d',$special,'-VerifyHashes') 1 @('Sha1Mismatch','long.bin')

$nestedLog = New-Fixture 'nested-log'
[IO.File]::WriteAllText("$nestedLog\C\fixture\nested_CopyLog.csv",'unlogged evidence')
Invoke-Check 'extended-nested-log-not-excluded' @('-d',$nestedLog) 1 @('UnloggedFile','nested_CopyLog.csv')
$rootFile = New-Fixture 'root-system-name-file'
[IO.File]::WriteAllText("$rootFile\System Volume Information",'ordinary unlogged root file')
Invoke-Check 'extended-root-system-file-directory' @('-d',$rootFile) 1 @('UnloggedFile','System Volume Information')
$rootFileZip = New-TestZip $rootFile 'root-system-name-file'
Invoke-Check 'extended-root-system-file-zip' @('-ZipPath',$rootFileZip) 1 @('UnloggedFile','System Volume Information')
$junction = New-Fixture 'reparse'
New-Item -ItemType Junction -Path "$junction\C\fixture\link" -Target "$junction\C\fixture\nested" | Out-Null
Invoke-Check 'extended-owned-reparse' @('-d',$junction,'-VerifyHashes') 1 @('ReparsePoint')

$ambiguousZip = New-TestZip $clean 'ambiguous-zip' '' @('another/test_CopyLog.csv')
Invoke-Check 'extended-ambiguous-archive-logs' @('-ZipPath',$ambiguousZip) 2 @('Expected exactly one CopyLog ZIP entry') @('PASS:')
$ambiguousRoot = New-TestZip $clean 'ambiguous-root' 'one/' @('two/C/fixture/ordinary.txt')
Invoke-Check 'extended-ambiguous-external-root' @('-ZipPath',$ambiguousRoot,'-CopyLogPath',"$clean\test_CopyLog.csv") 2 @('unambiguous ZIP collection root')
$unsupported = New-TestZip $clean 'unsupported'
$bytes = [IO.File]::ReadAllBytes($unsupported)
for ($index=0; $index -lt $bytes.Length-46; $index++) {
    if ([BitConverter]::ToUInt32($bytes,$index) -eq 0x02014b50) {
        $nameLength = [BitConverter]::ToUInt16($bytes,$index+28)
        $name = [Text.Encoding]::UTF8.GetString($bytes,$index+46,$nameLength)
        if ($name.EndsWith('ordinary.txt')) {
            [BitConverter]::GetBytes([uint16]99).CopyTo($bytes,$index+10)
            $localOffset = [BitConverter]::ToUInt32($bytes,$index+42)
            [BitConverter]::GetBytes([uint16]99).CopyTo($bytes,$localOffset+8)
            break
        }
    }
}
[IO.File]::WriteAllBytes($unsupported,$bytes)
Invoke-Check 'extended-unsupported-compression' @('-ZipPath',$unsupported,'-VerifyHashes') 2 @('Verification could not be completed') @('PASS:')

$coordinated = New-Fixture 'coordinated'
$log = "$coordinated\test_CopyLog.csv"
$write = [IO.File]::GetLastWriteTimeUtc($log)
$payload = "$coordinated\C\fixture\ordinary.txt"
$bytes = [IO.File]::ReadAllBytes($payload)
$bytes[0] = $bytes[0] -bxor 1
[IO.File]::WriteAllBytes($payload,$bytes)
[IO.File]::SetCreationTimeUtc($payload,$created)
[IO.File]::SetLastWriteTimeUtc($payload,$modified)
$rows = @(Import-Csv $log)
($rows | Where-Object SourceFile -like '*ordinary.txt').SourceFileSha1 = (Get-FileHash -LiteralPath $payload -Algorithm SHA1).Hash
$rows | Export-Csv $log -NoTypeInformation
[IO.File]::SetLastWriteTimeUtc($log,$write)
Invoke-Check 'extended-known-coordinated-edit-limitation' @('-d',$coordinated,'-VerifyMetadata','-CopyLogTimingAllowanceSeconds','2','-CollectionTimeZoneId','UTC') 0 @('within the supplied allowance')
$delay = New-Fixture 'finalization-delay'
[IO.File]::SetLastWriteTimeUtc("$delay\test_CopyLog.csv",[datetime]'2026-04-05T06:07:09.5Z')
Invoke-Check 'extended-test-only-finalization-delay' @('-d',$delay,'-CopyLogTimingAllowanceSeconds','2','-CollectionTimeZoneId','UTC') 0 @('within the supplied allowance')
Invoke-Check 'extended-negative-allowance' @('-d',$delay,'-CopyLogTimingAllowanceSeconds','-1') 1 @('validate argument')

foreach ($case in @('normal','post-completion','long-packaging','invalid','ambiguous')) {
    $root = New-Fixture "console-$case"
    $consoleTime = '2026-04-05 06:07:08.5'
    $zone = 'UTC'
    if ($case -eq 'post-completion') { $consoleTime = '2026-04-05 05:07:08.5' }
    if ($case -eq 'long-packaging') { $consoleTime = '2026-04-05 08:07:08.5' }
    if ($case -eq 'invalid') { $consoleTime = 'invalid' }
    if ($case -eq 'ambiguous') {
        $zone = 'Eastern Standard Time'
        $consoleTime = '2026-11-01 01:30:00'
        $rows = @(Import-Csv "$root\test_CopyLog.csv")
        foreach ($row in $rows) { $row.CopiedTimestamp = '2026-04-05T06:07:08.1234567Z' }
        $rows | Export-Csv "$root\test_CopyLog.csv" -NoTypeInformation
        [IO.File]::SetLastWriteTimeUtc("$root\test_CopyLog.csv",[datetime]'2026-04-05T06:07:08.124Z')
    }
    [IO.File]::WriteAllText("$root\test_ConsoleLog.txt","[$consoleTime | INF] Total execution time: 1 seconds")
    $expected = if ($case -eq 'post-completion') { 'suspicious relative to ConsoleLog completion' }
        elseif ($case -in 'invalid','ambiguous') { 'ConsoleLog completion context inconclusive' }
        else { 'no post-completion inconsistency detected' }
    Invoke-Check "console-$case" @('-d',$root,'-VerifyMetadata','-CopyLogTimingAllowanceSeconds','2','-CollectionTimeZoneId',$zone) 0 @($expected,'PASS:')
    if ($case -eq 'normal') {
        $zip = New-TestZip $root 'console-normal'
        Add-NtfsTimes $zip $root
        Invoke-Check 'console-internal-zip' @('-ZipPath',$zip,'-VerifyMetadata','-CopyLogTimingAllowanceSeconds','2','-CollectionTimeZoneId','UTC') 0 @($expected,'PASS:')
    }
}

$results | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $TestRoot 'results.json')
$failed = @($results | Where-Object { -not $_.Passed })
Write-Output "$($results.Count - $failed.Count)/$($results.Count) cases passed. Logs: $TestRoot"
if ($failed.Count) {
    $failed | Select-Object Name,ExpectedExit,ActualExit | Format-Table
    exit 1
}
exit 0
