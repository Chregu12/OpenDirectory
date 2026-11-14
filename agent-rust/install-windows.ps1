$ErrorActionPreference = 'Stop'
$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run install in an elevated terminal' }
$name = 'OpenDirectoryAgent'
$root = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'OpenDirectory'))
$config = [IO.Path]::GetFullPath($Options.config)
if (-not $config.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Service configuration must be inside ProgramData\OpenDirectory' }
$destination = [IO.Path]::GetFullPath($Options.destination)
$directory = Split-Path -Parent $destination
function NoLink($path) {
    if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points are not accepted for managed agent paths' }
}
function Restrict($path, $folder) {
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $path '/setowner' '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot set managed agent owner' }
    $system = if ($folder) { '*S-1-5-18:(OI)(CI)F' } else { '*S-1-5-18:F' }
    $admins = if ($folder) { '*S-1-5-32-544:(OI)(CI)F' } else { '*S-1-5-32-544:F' }
    & $icacls $path '/inheritance:r' '/grant:r' $system $admins | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot protect managed agent path' }
    $acl = Get-Acl -LiteralPath $path
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Unexpected explicit permission on managed agent path; review its ACL first' }
    }
}
$cursor = $config
while ($cursor -and $cursor.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { NoLink $cursor; $cursor = Split-Path -Parent $cursor }
$settings = Get-Content -LiteralPath $config -Raw | ConvertFrom-Json
if ($settings.ca_cert_path) {
    $ca = [IO.Path]::GetFullPath($settings.ca_cert_path)
    if (-not $ca.StartsWith($root + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Place the private CA certificate inside ProgramData\OpenDirectory before installing' }
    NoLink $ca
}
function Digest($text) { $sha=[Security.Cryptography.SHA256]::Create(); try { return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() } }
$marker = Join-Path $directory 'managed-task.sha256'
if (Test-Path -LiteralPath $directory) { NoLink $directory }
if (Test-Path -LiteralPath $marker) { NoLink $marker }
$task = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
$arguments = '--config-path "' + $config + '" run'
if ($config.Contains('"')) { throw 'Invalid configuration path' }
$owned = $task -and $task.Description -eq 'OpenDirectory managed device agent' -and @($task.Actions).Count -eq 1 -and $task.Actions[0].Execute -eq $destination -and $task.Actions[0].Arguments -eq $arguments -and (Test-Path -LiteralPath $marker) -and (Get-Content -LiteralPath $marker -Raw).Trim() -eq (Digest (Export-ScheduledTask -TaskName $name -TaskPath '\'))
if ($task -and -not $owned -and -not $Options.replace) { throw 'Different task exists; review it and explicitly use --replace-existing to back it up and replace it' }
New-Item -ItemType Directory -Force -Path $directory | Out-Null
NoLink $directory
if (Test-Path -LiteralPath $destination) { NoLink $destination }
Restrict $directory $true
if ($task -and -not $owned) {
    $backup = Join-Path $directory ('previous-task-' + [Guid]::NewGuid().ToString() + '.xml')
    Export-ScheduledTask -TaskName $name -TaskPath '\' | Set-Content -LiteralPath $backup -Encoding Unicode
    Restrict $backup $false
    Write-Host ('Previous task retained at ' + $backup)
}
$cursor = Split-Path -Parent $config
while ($cursor -and $cursor.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { Restrict $cursor $true; $cursor = Split-Path -Parent $cursor }
Restrict $config $false
if ($settings.ca_cert_path) { Restrict $ca $false }
if ($task) {
    Stop-ScheduledTask -TaskName $name -TaskPath '\'
    for ($i=0; $i -lt 30; $i++) { if ((Get-ScheduledTask -TaskName $name -TaskPath '\').State -ne 'Running') { break }; Start-Sleep -Milliseconds 250 }
    if ((Get-ScheduledTask -TaskName $name -TaskPath '\').State -eq 'Running') { throw 'Existing agent task did not stop' }
}
if (-not [string]::Equals([IO.Path]::GetFullPath($Options.source),$destination,[StringComparison]::OrdinalIgnoreCase)) {
    Copy-Item -LiteralPath $Options.source -Destination $destination -Force
}
Restrict $destination $false
$action = New-ScheduledTaskAction -Execute $destination -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$taskSettings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $name -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal -Settings $taskSettings -Description 'OpenDirectory managed device agent' -Force | Out-Null
(Digest (Export-ScheduledTask -TaskName $name -TaskPath '\')) | Set-Content -LiteralPath $marker -Encoding ASCII
Restrict $marker $false
Start-ScheduledTask -TaskName $name -TaskPath '\'
$running = $false
for ($i=0; $i -lt 30; $i++) { if ((Get-ScheduledTask -TaskName $name -TaskPath '\').State -eq 'Running') { $running=$true; break }; Start-Sleep -Milliseconds 250 }
if (-not $running) { throw 'Task registered but no running agent was confirmed' }
