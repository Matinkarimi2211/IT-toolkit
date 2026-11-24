#Requires -Version 5.1
<#
  SecureBrowser.ps1
  ------------------------------------------------------------------
  Password-protect browser data (Chrome, Edge, Firefox, Brave) on a
  Windows account whose password is shared by several people.

  How the pieces fit:
  * VeraCrypt     - an encrypted container with its own password,
                    independent of the Windows password.
  * Junctions     - each browser's data folder is moved unchanged into
                    the container; a link stays at the original path, so
                    the browser keeps working as before.
  * Shortcuts     - browser icons (desktop, Start menu, taskbar) ask for
                    the password first, then open the browser.
  * Task Scheduler- on lock (Win+L), user switch, sleep and sign-in the
                    browsers are closed and the container is locked.
                    Tabs come back on the next start.

  Requirements: Windows 10/11, PowerShell 5.1, VeraCrypt (offered via winget).

  Install  (sign in as the shared user, open a normal PowerShell window):
      powershell -NoProfile -ExecutionPolicy Bypass -File .\SecureBrowser.ps1

  Other actions:
      -Action Unlock      open the container (also: "Unlock Browsers" desktop icon)
      -Action Lock        close the browsers and lock now
      -Action Cleanup     delete the unprotected copies kept after moving
      -Action Uninstall   move all data back and remove everything
  Setup options:
      -DriveLetter R   -VaultPath <file>   -VaultSize 20G   -FileSystem NTFS|exFAT
      -NoSecureDesktop (if VeraCrypt reports a command-line error)

  Notes:
  * If each person can have their own Windows account, use that instead.
  * Domain PCs: check Group Policy (execution policy, BitLocker write
    protection, roaming AppData) and your IT rules first.
  * Test on a non-critical PC first and keep a copy of the vault file.
    Losing the vault file or its password means losing the browser data.

  Provided as-is, without warranty.
#>
[CmdletBinding()]
param(
    [ValidateSet('Setup', 'Guard', 'Lock', 'Unlock', 'Open', 'Cleanup', 'Uninstall')]
    [string]$Action = 'Setup',
    [string]$Browser = '',
    [string]$ArgsB64 = '',
    [ValidatePattern('^[D-Zd-z]:?$')]
    [string]$DriveLetter = 'Z',
    [string]$VaultPath = '',
    [ValidatePattern('^(\d+[MGmg])?$')]
    [string]$VaultSize = '',
    [ValidateSet('NTFS', 'exFAT')]
    [string]$FileSystem = 'NTFS',
    [switch]$NoSecureDesktop
)

$ErrorActionPreference = 'Stop'

$ScriptParams    = $PSBoundParameters
$ThisScript      = $PSCommandPath
$InstallDir      = Join-Path $env:LOCALAPPDATA 'SecureBrowser'
$InstalledScript = Join-Path $InstallDir 'SecureBrowser.ps1'
$ConfigPath      = Join-Path $InstallDir 'config.json'
$RestorePath     = Join-Path $InstallDir 'restore.txt'
$LockTask        = 'SecureBrowser-AutoLock'
$GuardTask       = 'SecureBrowser-Guard'
$MarkerName      = '.sbvault2'
$PowerShellExe   = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$Desktop         = [Environment]::GetFolderPath('Desktop')
$LockShortcut    = Join-Path $Desktop 'Lock Browsers.lnk'
$UnlockShortcut  = Join-Path $Desktop 'Unlock Browsers.lnk'
$LnkBackupDir    = Join-Path $InstallDir 'shortcut-backup'
$DidMount        = $false
$StartupShortcut = Join-Path ([Environment]::GetFolderPath('Startup')) 'SecureBrowser Guard.lnk'
$Session         = (Get-Process -Id $PID).SessionId
$Interactive     = $Action -in @('Setup', 'Cleanup', 'Uninstall')
$Cfg             = $null

$ATTR_DIRECTORY  = 16
$ATTR_REPARSE    = 1024

# =================================================================== helpers

function Arr($x) { @($x | Where-Object { $null -ne $_ }) }

function Notify([string]$Text) {
    if ($Interactive) { Write-Warning $Text }
    else { $null = (New-Object -ComObject WScript.Shell).Popup($Text, 0, 'Secure Browser', 48) }
}

function Save-Config {
    [void][IO.Directory]::CreateDirectory($InstallDir)
    $json = $script:Cfg | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText($ConfigPath, $json, (New-Object Text.UTF8Encoding $false))
}

function Set-CfgProp([string]$Name, $Value) {
    if ($script:Cfg.PSObject.Properties[$Name]) { $script:Cfg.$Name = $Value }
    else { $script:Cfg | Add-Member -NotePropertyName $Name -NotePropertyValue $Value }
}

function Read-Config {
    if (-not [IO.File]::Exists($ConfigPath)) { return $null }
    return ([IO.File]::ReadAllText($ConfigPath, [Text.Encoding]::UTF8) | ConvertFrom-Json)
}

function Get-RestoreKeys {
    if (-not [IO.File]::Exists($RestorePath)) { return @() }
    return @([IO.File]::ReadAllLines($RestorePath) | Where-Object { $_ })
}

function Set-RestoreKeys($Keys) {
    [void][IO.Directory]::CreateDirectory($InstallDir)
    [IO.File]::WriteAllLines($RestorePath, [string[]]@(Arr $Keys))
}

# =================================================================== vault

function Get-Root { return ([string]$script:Cfg.Drive) + ':\' }

function Test-VaultOpen { return [IO.File]::Exists((Get-Root) + $MarkerName) }

function Open-Vault {
    $script:DidMount = $false
    if (Test-VaultOpen) { return $true }
    # only one password box at a time (guard and shortcuts may ask together)
    $m = New-Object System.Threading.Mutex($false, 'Local\SecureBrowser-Open')
    $got = $false
    try {
        try { $got = $m.WaitOne(300000) } catch [System.Threading.AbandonedMutexException] { $got = $true }
        if (Test-VaultOpen) { return $true }
        $ok = Mount-VaultNow
        if ($ok) { $script:DidMount = $true }
        return $ok
    } finally {
        if ($got) { try { $m.ReleaseMutex() } catch { } }
        $m.Dispose()
    }
}

function Mount-VaultNow {
    $root = Get-Root
    if ([IO.Directory]::Exists($root)) {
        Notify ("Drive {0}: is used by another disk. Remove it, or run setup again with -DriveLetter." -f $Cfg.Drive)
        return $false
    }
    if (-not [IO.File]::Exists($Cfg.VaultPath)) {
        Notify "Encrypted vault not found: $($Cfg.VaultPath)"
        return $false
    }
    # No /password: VeraCrypt shows its own password box.
    $a = '/volume "{0}" /letter {1} /cache n /history n /quit' -f $Cfg.VaultPath, $Cfg.Drive
    if ($Cfg.SecureDesktop) { $a += ' /secureDesktop y' }
    $p = Start-Process -FilePath $Cfg.VeraCrypt -ArgumentList $a -PassThru
    $deadline = (Get-Date).AddMinutes(5)
    while ((Get-Date) -lt $deadline -and -not [IO.Directory]::Exists($root)) {
        if ($p.HasExited) {
            for ($i = 0; $i -lt 8 -and -not [IO.Directory]::Exists($root); $i++) { Start-Sleep -Milliseconds 250 }
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not [IO.Directory]::Exists($root)) { return $false }      # cancelled / wrong password
    $marker = $root + $MarkerName
    if (-not [IO.File]::Exists($marker)) {
        [IO.File]::WriteAllText($marker, 'SecureBrowser vault')
        [IO.File]::SetAttributes($marker, [IO.FileAttributes]::Hidden)
    }
    Repair-Links
    return $true
}

function Close-Vault {
    $root = Get-Root
    foreach ($force in @($false, $true)) {
        if (-not [IO.Directory]::Exists($root)) { return }
        $a = '/dismount {0} /wipecache /quit /silent' -f $Cfg.Drive
        if ($force) { $a += ' /force' }
        $p = Start-Process -FilePath $Cfg.VeraCrypt -ArgumentList $a -PassThru -WindowStyle Hidden
        [void]$p.WaitForExit(20000)
        for ($i = 0; $i -lt 8 -and [IO.Directory]::Exists($root); $i++) { Start-Sleep -Milliseconds 250 }
    }
}

# =================================================================== links (junctions)

# ours | missing | realdir | otherlink | file
function Get-LinkState([string]$Path, [string]$Target) {
    try { $attr = [int][IO.File]::GetAttributes($Path) } catch { return 'missing' }
    if (($attr -band $ATTR_DIRECTORY) -eq 0) { return 'file' }
    if (($attr -band $ATTR_REPARSE) -eq 0) { return 'realdir' }
    $t = $null
    try { $t = @((Get-Item -LiteralPath $Path -Force).Target)[0] } catch { }
    if ($t) {
        $t = ([string]$t) -replace '^\\\\\?\\|^\\\?\?\\', ''
        if ($t.TrimEnd('\') -ieq $Target.TrimEnd('\')) { return 'ours' }
        return 'otherlink'
    }
    # target not readable: if the vault is open, check with a probe file
    if ([IO.Directory]::Exists($Target)) {
        $probe = '.sb-probe-' + [guid]::NewGuid().ToString('N')
        $inTarget = $Target.TrimEnd('\') + '\' + $probe
        try {
            [IO.File]::WriteAllText($inTarget, '')
            if ([IO.File]::Exists($Path.TrimEnd('\') + '\' + $probe)) { return 'ours' }
        } catch { } finally { try { [IO.File]::Delete($inTarget) } catch { } }
    }
    return 'otherlink'
}

function New-Junction([string]$Path, [string]$Target) {
    $parent = Split-Path -Parent $Path
    if (-not [IO.Directory]::Exists($parent)) { [void][IO.Directory]::CreateDirectory($parent) }
    try {
        New-Item -ItemType Junction -Path $Path -Value $Target -ErrorAction Stop | Out-Null
    } catch {
        & cmd.exe /c mklink /J $Path $Target | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not create link: $Path" }
    }
}

# Called after every unlock: make sure every protected folder still points into the vault.
function Repair-Links {
    $root = Get-Root
    foreach ($l in (Arr $Cfg.Links)) {
        try {
            $target = $root + $l.Rel
            if (-not [IO.Directory]::Exists($target)) { [void][IO.Directory]::CreateDirectory($target) }
            switch (Get-LinkState $l.Path $target) {
                'ours'    { }
                'missing' { New-Junction $l.Path $target }
                'realdir' {
                    $stray = $l.Path + '.sb-stray-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
                    [IO.Directory]::Move($l.Path, $stray)
                    New-Junction $l.Path $target
                    Notify "A new unprotected folder had appeared and was moved aside:`n$stray"
                }
                default   { Notify "Not protected (unexpected item): $($l.Path)" }
            }
        } catch { Notify "Could not check $($l.Path): $($_.Exception.Message)" }
    }
}

function Copy-Verified([string]$Src, [string]$Dst) {
    [void][IO.Directory]::CreateDirectory($Dst)
    & robocopy.exe $Src $Dst /E /COPY:DAT /DCOPY:DAT /XJ /R:2 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { return $false }
    # verification pass: list-only, must find nothing left to copy
    & robocopy.exe $Src $Dst /E /L /XJ /FFT /R:0 /W:0 /NFL /NDL /NJH /NJS /NP | Out-Null
    return (($LASTEXITCODE -band 0x1D) -eq 0)
}

function Remove-Tree([string]$Path) {
    $ErrorActionPreference = 'Continue'
    if (-not $Path -or $Path.TrimEnd('\').Length -le 3) { return $false }
    try { $attr = [int][IO.File]::GetAttributes($Path) } catch { return $true }
    if ($attr -band $ATTR_REPARSE) { [IO.Directory]::Delete($Path); return $true }   # a link: remove only the link
    & cmd.exe /c rd /s /q $Path | Out-Null                                            # rd never follows links
    if ([IO.Directory]::Exists($Path)) {
        $empty = Join-Path $env:TEMP ('sb-empty-' + [guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($empty)
        & robocopy.exe $empty $Path /MIR /XJ /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
        [IO.Directory]::Delete($empty)
        try { [IO.Directory]::Delete($Path, $true) } catch { }
    }
    return (-not [IO.Directory]::Exists($Path))
}

function Get-DirSize([string]$Path) {
    $m = Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
         Measure-Object -Property Length -Sum
    if ($m -and $m.Sum) { return [int64]$m.Sum }
    return [int64]0
}

# =================================================================== browser processes

function Get-BrowserByProcess([string]$Name) {
    @(Arr $Cfg.Browsers) | Where-Object { $_.Process -ieq $Name } | Select-Object -First 1
}

function Get-BrowserProcs {
    $names = @(Arr $Cfg.Browsers | ForEach-Object { $_.Process })
    $dirs  = @(Arr $Cfg.Browsers | ForEach-Object { $_.InstallDir } | Where-Object { $_ } |
               ForEach-Object { ([string]$_).TrimEnd('\') + '\' })
    @(Get-CimInstance -ClassName Win32_Process -Property ProcessId, Name, CommandLine, ExecutablePath, SessionId -ErrorAction SilentlyContinue |
        Where-Object {
            if ([int]$_.SessionId -ne $Session -or [int]$_.ProcessId -eq $PID) { return $false }
            if ($names -contains $_.Name) { return $true }
            $exe = [string]$_.ExecutablePath
            if (-not $exe) { return $false }
            foreach ($d in $dirs) { if ($exe.StartsWith($d, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
            return $false
        })
}

# main | silent | child | helper | bgtask
function Get-ProcKind($P) {
    $c = [string]$P.CommandLine
    if ($c -match '(^|\s)--?backgroundtask(\s|$)') { return 'bgtask' }
    if ($c -match '\s--type=' -or $c -match '\s-contentproc(\s|$)') { return 'child' }
    if (-not (Get-BrowserByProcess $P.Name)) { return 'helper' }
    if ($c -match '--no-startup-window|--headless') { return 'silent' }
    return 'main'
}

function Stop-Procs($Procs) {
    $ids = @(Arr $Procs | ForEach-Object { [int]$_.ProcessId })
    if ($ids.Count -eq 0) { return }
    Stop-Process -Id $ids -Force -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt 20; $i++) {
        if (-not (Get-Process -Id $ids -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 250
    }
}

function Get-LaunchArgs($P) {
    $c   = ([string]$P.CommandLine).Trim()
    $exe = [string]$P.ExecutablePath
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 0) { return $c.Substring($end + 1).Trim() }
        return ''
    }
    if ($exe -and $c.StartsWith($exe, [StringComparison]::OrdinalIgnoreCase)) { return $c.Substring($exe.Length).Trim() }
    $sp = $c.IndexOf(' ')
    if ($sp -gt 0) { return $c.Substring($sp + 1).Trim() }
    return ''
}

function New-Launch($P) {
    $exe = [string]$P.ExecutablePath
    if (-not $exe) { $b = Get-BrowserByProcess $P.Name; if ($b) { $exe = [string]$b.Exe } }
    [pscustomobject]@{ Name = [string]$P.Name; Exe = $exe; Args = (Get-LaunchArgs $P) }
}

function Start-Launches($Launches) {
    $restore = @(Get-RestoreKeys)
    $seen = @{}
    foreach ($l in @($Launches)) {
        if (-not $l.Exe) { continue }
        $k = ($l.Exe + '|' + $l.Args).ToLowerInvariant()
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $argLine = $l.Args
        $b = Get-BrowserByProcess $l.Name
        if ($b -and $b.Chromium -and ($restore -contains $b.Key)) {
            # browser was closed by the lock: bring its tabs back
            $argLine = ('--restore-last-session ' + $argLine).Trim()
            $restore = @($restore | Where-Object { $_ -ne $b.Key })
        }
        try {
            if ($argLine) { Start-Process -FilePath $l.Exe -ArgumentList $argLine }
            else { Start-Process -FilePath $l.Exe }
        } catch { }
    }
    Set-RestoreKeys $restore
}

# Kill every browser process (they cannot work while the vault is locked) and
# remember the ones the user started, so they can be started again after the password.
function Invoke-Sweep($Launches, $Ignore) {
    $kill = @()
    foreach ($p in (Get-BrowserProcs)) {
        $kind = Get-ProcKind $p
        if ($kind -eq 'bgtask') { if ($Ignore) { [void]$Ignore.Add([int]$p.ProcessId) }; continue }
        $kill += $p
        if ($kind -eq 'main') { [void]$Launches.Add((New-Launch $p)) }
    }
    Stop-Procs $kill
}

function Invoke-LockedLaunch($Ignore) {
    $launches = New-Object System.Collections.ArrayList
    Invoke-Sweep $launches $Ignore
    if ($launches.Count -eq 0) { return }          # only background starts (e.g. Edge startup boost)
    $ok = Open-Vault
    if ($DidMount -or -not $ok) { Invoke-Sweep $launches $Ignore }   # anything started while the password box was open
    if ($ok) { Start-Launches $launches }
}

function Stop-BrokenBrowsers {
    Stop-Procs (@(Get-BrowserProcs) | Where-Object { (Get-ProcKind $_) -ne 'bgtask' })
}

# "Unlock Browsers" shortcut, and the first step of every browser shortcut
function Invoke-Unlock {
    if (Test-VaultOpen) { return $true }
    Stop-BrokenBrowsers                            # instances started while locked cannot work
    if (-not (Open-Vault)) { return $false }
    if ($DidMount) { Stop-BrokenBrowsers }
    return $true
}

# Browser shortcuts point here: ask for the password if needed, then start the browser.
function Invoke-Open {
    if (-not (Invoke-Unlock)) { return }
    $b = @(Arr $Cfg.Browsers) | Where-Object { $_.Key -eq $Browser } | Select-Object -First 1
    if (-not $b -or -not $b.Exe -or -not [IO.File]::Exists([string]$b.Exe)) { Notify "Browser not found: $Browser"; return }
    $argLine = ''
    if ($ArgsB64) { try { $argLine = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ArgsB64)) } catch { } }
    Start-Launches @([pscustomobject]@{ Name = [string]$b.Process; Exe = [string]$b.Exe; Args = $argLine })
}

# Point every browser shortcut (desktop, Start menu, taskbar pins) at "-Action Open".
# The original .lnk is backed up first; Uninstall puts it back.
function Update-BrowserShortcuts {
    $exeMap = @{}
    foreach ($b in (Arr $Cfg.Browsers)) { if ($b.Exe) { $exeMap[([string]$b.Exe).ToLowerInvariant()] = $b } }
    if ($exeMap.Count -eq 0) { return 0 }
    $ws = New-Object -ComObject WScript.Shell
    [void][IO.Directory]::CreateDirectory($LnkBackupDir)
    $records = @(Arr $Cfg.ShortcutBackups)
    $count = 0
    $places = @(
        @{ Path = [Environment]::GetFolderPath('Desktop');                Recurse = $false },
        @{ Path = [Environment]::GetFolderPath('CommonDesktopDirectory'); Recurse = $false },
        @{ Path = [Environment]::GetFolderPath('StartMenu');              Recurse = $true },
        @{ Path = [Environment]::GetFolderPath('CommonStartMenu');        Recurse = $true },
        @{ Path = (Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch'); Recurse = $true }
    )
    foreach ($pl in $places) {
        if (-not $pl.Path -or -not [IO.Directory]::Exists($pl.Path)) { continue }
        $files = @(Get-ChildItem -LiteralPath $pl.Path -Filter '*.lnk' -File -Force -Recurse:$pl.Recurse -ErrorAction SilentlyContinue)
        foreach ($f in $files) {
            $bak = $null
            try {
                $lnk = $ws.CreateShortcut($f.FullName)
                $target = [string]$lnk.TargetPath
                if (-not $target -or -not $exeMap.ContainsKey($target.ToLowerInvariant())) { continue }
                $b = $exeMap[$target.ToLowerInvariant()]
                $bak = Join-Path $LnkBackupDir ([guid]::NewGuid().ToString('N') + '.lnk')
                [IO.File]::Copy($f.FullName, $bak, $true)
                $origArgs = [string]$lnk.Arguments
                $icon     = [string]$lnk.IconLocation
                $a = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledScript`" -Action Open -Browser $($b.Key)"
                if ($origArgs) { $a += ' -ArgsB64 ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($origArgs)) }
                $lnk.TargetPath  = $PowerShellExe
                $lnk.Arguments   = $a
                $lnk.WindowStyle = 7
                if (-not $icon -or $icon.StartsWith(',')) { $lnk.IconLocation = "$target,0" }
                $lnk.Save()
                $records += [pscustomobject]@{ Path = $f.FullName; Backup = $bak }
                $bak = $null
                $count++
            } catch {
                if ($bak) { try { [IO.File]::Delete($bak) } catch { } }   # e.g. no permission for all-users shortcuts
            }
        }
    }
    Set-CfgProp 'ShortcutBackups' $records
    if ($count -gt 0) { Save-Config }
    return $count
}

function Restore-BrowserShortcuts {
    $left = @()
    foreach ($r in (Arr $Cfg.ShortcutBackups)) {
        try {
            if ([IO.File]::Exists($r.Backup)) {
                [IO.File]::Copy($r.Backup, $r.Path, $true)
                [IO.File]::Delete($r.Backup)
            }
        } catch { $left += $r }
    }
    Set-CfgProp 'ShortcutBackups' $left
    Save-Config
}

# =================================================================== guard / lock

function Invoke-Guard {
    $ErrorActionPreference = 'Continue'
    $mutex = New-Object System.Threading.Mutex($false, 'Local\SecureBrowser-Guard')
    try { if (-not $mutex.WaitOne(0)) { return } } catch [System.Threading.AbandonedMutexException] { }
    $short  = @(Arr $Cfg.Browsers | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension([string]$_.Process) })
    $ignore = New-Object 'System.Collections.Generic.HashSet[int]'
    while ($true) {
        $wait = 250
        try {
            if (Test-VaultOpen) {
                $ignore.Clear()
                $wait = 1500
            } else {
                $live = @(Get-Process -Name $short -ErrorAction SilentlyContinue |
                          Where-Object { $_.SessionId -eq $Session -and -not $ignore.Contains($_.Id) })
                if ($live.Count -gt 0) { Invoke-LockedLaunch $ignore }
            }
        } catch { }
        Start-Sleep -Milliseconds $wait
    }
}

function Invoke-Lock {
    $ErrorActionPreference = 'Continue'
    try {
        if (Test-VaultOpen) {
            try {
                $keys = @(); $kill = @()
                foreach ($p in (Get-BrowserProcs)) {
                    $kind = Get-ProcKind $p
                    if ($kind -eq 'bgtask') { continue }
                    $kill += $p
                    if ($kind -eq 'main') {
                        $b = Get-BrowserByProcess $p.Name
                        if ($b -and ($keys -notcontains $b.Key)) { $keys += [string]$b.Key }
                    }
                }
                Set-RestoreKeys $keys
                Stop-Procs $kill
            } catch { }
            Close-Vault
        }
        try { [void](Update-BrowserShortcuts) } catch { }   # catch shortcuts re-created by browser updates
    } finally {
        Start-ScheduledTask -TaskName $GuardTask -ErrorAction SilentlyContinue
    }
}

function Start-Guard {
    try { Start-ScheduledTask -TaskName $GuardTask -ErrorAction Stop; return } catch { }
    Start-Process -FilePath $PowerShellExe -WindowStyle Hidden -ArgumentList `
        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledScript`" -Action Guard"
}

function Stop-Guard {
    Stop-ScheduledTask -TaskName $GuardTask -ErrorAction SilentlyContinue
    Get-CimInstance -ClassName Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object {
            $c = [string]$_.CommandLine
            [int]$_.ProcessId -ne $PID -and $c -match 'SecureBrowser\.ps1' -and $c -match '-Action\s+Guard'
        } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

# =================================================================== setup helpers

function Find-Exe([string]$AppPathName, [string[]]$Candidates) {
    foreach ($hive in 'HKCU:', 'HKLM:') {
        $key = "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$AppPathName"
        try {
            $p = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).'(default)'
            if ($p) { $p = $p.Trim('"'); if (Test-Path -LiteralPath $p) { return $p } }
        } catch { }
    }
    foreach ($c in $Candidates) { if ($c -and (Test-Path -LiteralPath $c)) { return $c } }
    return $null
}

function Get-UsedDriveLetters {
    $ErrorActionPreference = 'Continue'
    $used = @([IO.DriveInfo]::GetDrives() | ForEach-Object { ([string]$_.Name).Substring(0, 1).ToUpper() })
    # mapped network drives, including disconnected ones
    $used += @(& net.exe use | ForEach-Object { if ($_ -match '(?<![A-Za-z])([A-Za-z]):\s+\\\\') { $Matches[1].ToUpper() } })
    return @($used | Select-Object -Unique)
}

function Get-FreeDriveLetter {
    $used = Get-UsedDriveLetters
    foreach ($c in 'Z', 'Y', 'X', 'W', 'V', 'U', 'T', 'S', 'R', 'Q', 'P', 'O', 'N', 'M') {
        if ($used -notcontains $c) { return $c }
    }
    return $null
}

function Find-VeraCrypt {
    Find-Exe 'VeraCrypt.exe' @("$env:ProgramFiles\VeraCrypt\VeraCrypt.exe", "${env:ProgramFiles(x86)}\VeraCrypt\VeraCrypt.exe")
}

function Get-BrowserDefinitions {
    $L = $env:LOCALAPPDATA; $R = $env:APPDATA; $PF = $env:ProgramFiles; $PF86 = ${env:ProgramFiles(x86)}
    $chrome  = Find-Exe 'chrome.exe'  @("$PF\Google\Chrome\Application\chrome.exe", "$PF86\Google\Chrome\Application\chrome.exe", "$L\Google\Chrome\Application\chrome.exe")
    $edge    = Find-Exe 'msedge.exe'  @("$PF86\Microsoft\Edge\Application\msedge.exe", "$PF\Microsoft\Edge\Application\msedge.exe")
    $brave   = Find-Exe 'brave.exe'   @("$PF\BraveSoftware\Brave-Browser\Application\brave.exe", "$PF86\BraveSoftware\Brave-Browser\Application\brave.exe", "$L\BraveSoftware\Brave-Browser\Application\brave.exe")
    $firefox = Find-Exe 'firefox.exe' @("$PF\Mozilla Firefox\firefox.exe", "$PF86\Mozilla Firefox\firefox.exe", "$L\Mozilla Firefox\firefox.exe")
    return @(
        @{ Key = 'Chrome';  Process = 'chrome.exe';  Chromium = $true;  Exe = $chrome
           Links = @(@{ Path = "$L\Google\Chrome\User Data"; Rel = 'Chrome\User Data' }) },
        @{ Key = 'Edge';    Process = 'msedge.exe';  Chromium = $true;  Exe = $edge
           Links = @(@{ Path = "$L\Microsoft\Edge\User Data"; Rel = 'Edge\User Data' }) },
        @{ Key = 'Brave';   Process = 'brave.exe';   Chromium = $true;  Exe = $brave
           Links = @(@{ Path = "$L\BraveSoftware\Brave-Browser\User Data"; Rel = 'Brave\User Data' }) },
        @{ Key = 'Firefox'; Process = 'firefox.exe'; Chromium = $false; Exe = $firefox
           Links = @(@{ Path = "$R\Mozilla\Firefox"; Rel = 'Firefox\Roaming' },
                     @{ Path = "$L\Mozilla\Firefox"; Rel = 'Firefox\Local' }) }
    )
}

function Read-SecretPlain([string]$Prompt) {
    $s = Read-Host -Prompt $Prompt -AsSecureString
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

function New-Vault([string]$Path, [string]$Size, [string]$Fs, [string]$VeraCrypt) {
    $dir = Split-Path -Parent $VeraCrypt
    $fmt = @('VeraCrypt Format.exe', 'VeraCrypt Format-x64.exe') | ForEach-Object { Join-Path $dir $_ } |
           Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $fmt) { throw "'VeraCrypt Format.exe' was not found next to $VeraCrypt" }
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $Path))

    Write-Host ''
    Write-Host 'Choose the browser password.' -ForegroundColor Cyan
    Write-Host 'English keyboard characters only. If it is forgotten, the browser data is GONE.'
    while ($true) {
        $p1 = Read-SecretPlain 'Password'
        $p2 = Read-SecretPlain 'Repeat password'
        if ($p1 -cne $p2)              { Write-Warning 'Passwords do not match.'; continue }
        if ($p1.Length -lt 8)          { Write-Warning 'Use at least 8 characters.'; continue }
        if ($p1 -match '[^\x20-\x7E]') { Write-Warning 'Only English keyboard characters are allowed.'; continue }
        if ($p1.Contains('"'))         { Write-Warning 'The " character is not allowed.'; continue }
        if ($p1.Length -lt 20) {
            Write-Warning 'VeraCrypt recommends 20+ characters (3-4 random words work well).'
            if ((Read-Host 'Use this password anyway? (y/n)') -notmatch '^[yY]') { continue }
        }
        break
    }

    Write-Host "Creating the $Size encrypted vault. This can take a few minutes."
    Write-Host 'If Windows asks for permission, click Yes.'
    $fmtArgs = '/create "{0}" /size {1} /password "{2}" /encryption AES /hash sha512 /filesystem {3} /silent' -f $Path, $Size, $p1, $Fs
    $proc = Start-Process -FilePath $fmt -ArgumentList $fmtArgs -PassThru
    $null = $proc.Handle
    $proc.WaitForExit()
    $code = $proc.ExitCode
    $p1 = $null; $p2 = $null; $fmtArgs = $null; [GC]::Collect()

    if ($code -ne 0 -or -not (Test-Path -LiteralPath $Path)) {
        Remove-Item -LiteralPath $Path -ErrorAction SilentlyContinue
        throw ("Creating the vault failed (exit code $code).`n" +
               "Try again with -FileSystem exFAT or a longer password, or create it by hand in VeraCrypt " +
               "(Create Volume > file container, $Size) at:`n  $Path`nthen run this script again.")
    }
    Write-Host 'Vault created.' -ForegroundColor Green
}

function New-Shortcut([string]$File, [string]$Arguments, [string]$Icon) {
    $ws  = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut($File)
    $lnk.TargetPath       = $PowerShellExe
    $lnk.Arguments        = $Arguments
    $lnk.WindowStyle      = 7
    $lnk.WorkingDirectory = $InstallDir
    if ($Icon) { $lnk.IconLocation = $Icon }
    $lnk.Save()
}

function Register-Tasks {
    $userId    = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $ns        = 'Root/Microsoft/Windows/TaskScheduler'
    $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
    $base      = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledScript`" -Action"

    # ---- lock task: lock / switch user / RDP disconnect / sleep / sign-in
    $sessionTriggers = @()
    $ssc = Get-CimClass -Namespace $ns -ClassName MSFT_TaskSessionStateChangeTrigger
    foreach ($state in 7, 2, 4) {   # 7 = lock, 2 = console disconnect (switch user), 4 = RDP disconnect
        $sessionTriggers += New-CimInstance -CimClass $ssc -ClientOnly -Property @{
            StateChange = [uint32]$state; UserId = $userId; Enabled = $true }
    }
    $logon = New-ScheduledTaskTrigger -AtLogOn -User $userId
    $sleep = $null
    try {
        $ev  = Get-CimClass -Namespace $ns -ClassName MSFT_TaskEventTrigger
        $sub = '<QueryList><Query Id="0" Path="System"><Select Path="System">' +
               "*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=42]]" +
               '</Select></Query></QueryList>'
        $sleep = New-CimInstance -CimClass $ev -ClientOnly -Property @{ Subscription = $sub; Enabled = $true }
    } catch { }

    $sets = @()
    if ($sleep) { $sets += , @($sessionTriggers + $logon + $sleep) }
    $sets += , @($sessionTriggers + $logon)
    $sets += , @($sessionTriggers)

    $lockAction   = New-ScheduledTaskAction -Execute $PowerShellExe -Argument "$base Lock"
    $lockSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                        -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew
    Unregister-ScheduledTask -TaskName $LockTask -Confirm:$false -ErrorAction SilentlyContinue
    $done = $false
    foreach ($set in $sets) {
        try {
            Register-ScheduledTask -TaskName $LockTask -Action $lockAction -Trigger $set -Principal $principal `
                -Settings $lockSettings -Description 'Secure Browser: close browsers and lock the vault.' -ErrorAction Stop | Out-Null
            $done = $true; break
        } catch { }
    }
    if (-not $done) { throw 'Could not register the lock task in Task Scheduler.' }
    Write-Host ("Task      : $LockTask ({0} triggers)" -f (Get-ScheduledTask -TaskName $LockTask).Triggers.Count)

    # ---- guard task: runs in the background while the user is signed in
    $guardAction   = New-ScheduledTaskAction -Execute $PowerShellExe -Argument "$base Guard"
    $guardSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd `
                        -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
                        -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)
    Unregister-ScheduledTask -TaskName $GuardTask -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $StartupShortcut -ErrorAction SilentlyContinue
    try {
        Register-ScheduledTask -TaskName $GuardTask -Action $guardAction -Trigger $logon -Principal $principal `
            -Settings $guardSettings -Description 'Secure Browser: asks for the password when a browser starts.' -ErrorAction Stop | Out-Null
        Write-Host "Task      : $GuardTask"
    } catch {
        New-Shortcut $StartupShortcut "$base Guard" $null
        Write-Host 'Guard     : started from the Startup folder'
    }
}

# =================================================================== actions

function Invoke-Setup {
    Write-Host ''
    Write-Host "=== Secure Browser v2 - setup for user $env:USERNAME ===" -ForegroundColor Cyan
    Write-Host ''

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                   [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Warning 'This window runs as administrator. That is fine ONLY if it was opened from the shared account itself.'
        if ((Read-Host 'Continue? (y/n)') -notmatch '^[yY]') { return }
    }

    # ---- VeraCrypt
    $vc = Find-VeraCrypt
    if (-not $vc -and (Get-Command winget -ErrorAction SilentlyContinue)) {
        if ((Read-Host 'VeraCrypt is not installed. Install it now with winget? (y/n)') -match '^[yY]') {
            winget install --id IDRIX.VeraCrypt -e --accept-source-agreements --accept-package-agreements
            $vc = Find-VeraCrypt
        }
    }
    if (-not $vc) { throw 'VeraCrypt was not found. Install it from https://www.veracrypt.fr and run this script again.' }
    Write-Host "VeraCrypt : $vc"

    # ---- settings (keep the previous ones on a re-run)
    $prev  = Read-Config
    $vault = $VaultPath
    if (-not $vault) { if ($prev) { $vault = [string]$prev.VaultPath } else { $vault = Join-Path $InstallDir 'browsers.hc' } }
    if ($ScriptParams.ContainsKey('DriveLetter')) { $drive = $DriveLetter.TrimEnd(':').ToUpper() }
    elseif ($prev) { $drive = [string]$prev.Drive }
    else { $drive = Get-FreeDriveLetter }
    if (-not $drive) { throw 'No free drive letter was found. Run again with -DriveLetter.' }
    $root  = $drive + ':\'
    if (((Get-UsedDriveLetters) -contains $drive) -and -not [IO.File]::Exists($root + $MarkerName)) {
        throw "Drive ${drive}: is already in use (a disk or a network drive). Run again with another letter, e.g. -DriveLetter R"
    }
    Write-Host "Drive     : ${drive}:"

    # ---- browsers
    $found = @()
    foreach ($d in (Get-BrowserDefinitions)) {
        $hasData = @($d.Links | Where-Object { (Get-LinkState $_.Path ($root + $_.Rel)) -ne 'missing' }).Count -gt 0
        if ($d.Exe -or $hasData) { $found += $d }
    }
    if ($found.Count -eq 0) { throw 'No supported browser was found.' }
    Write-Host ('Browsers  : ' + (($found | ForEach-Object { $_.Key }) -join ', '))
    $unsupported = @{ 'Opera' = "$env:APPDATA\Opera Software"; 'Vivaldi' = "$env:LOCALAPPDATA\Vivaldi\User Data"
                      'Yandex' = "$env:LOCALAPPDATA\Yandex\YandexBrowser\User Data" }
    foreach ($k in $unsupported.Keys) {
        if (Test-Path -LiteralPath $unsupported[$k]) { Write-Warning "$k is installed but is NOT protected by this script." }
    }

    $browsers = @()
    foreach ($d in $found) {
        $inst = $null
        if ($d.Exe) { $inst = Split-Path -Parent $d.Exe }
        $browsers += [pscustomobject]@{ Key = $d.Key; Process = $d.Process; Exe = $d.Exe; InstallDir = $inst; Chromium = $d.Chromium }
    }
    $prevLinks = @(); $prevBackups = @(); $prevShortcuts = @()
    if ($prev) {
        $prevLinks = @(Arr $prev.Links); $prevBackups = @(Arr $prev.Backups)
        if ($prev.PSObject.Properties['ShortcutBackups']) { $prevShortcuts = @(Arr $prev.ShortcutBackups) }
    }
    $script:Cfg = [pscustomobject]@{
        Version       = 2
        VaultPath     = $vault
        Drive         = $drive
        VeraCrypt     = $vc
        SecureDesktop = (-not $NoSecureDesktop)
        Browsers      = $browsers
        Links         = $prevLinks
        Backups       = $prevBackups
        ShortcutBackups = $prevShortcuts
    }
    Save-Config
    if ($ThisScript -and ($ThisScript -ne $InstalledScript)) {
        Copy-Item -LiteralPath $ThisScript -Destination $InstalledScript -Force
    }
    Stop-Guard
    Disable-ScheduledTask -TaskName $LockTask -ErrorAction SilentlyContinue | Out-Null   # re-created below

    # ---- close browsers
    Write-Host ''
    Write-Host 'Close ALL browser windows now (Chrome, Edge, Firefox, Brave), then press Enter.' -ForegroundColor Yellow
    Write-Host 'Do not lock the PC or open a browser until setup has finished.' -ForegroundColor Yellow
    [void](Read-Host)
    Stop-Procs (Get-BrowserProcs)

    # ---- plan
    $plan = @()
    foreach ($d in $found) {
        foreach ($l in $d.Links) {
            $state = Get-LinkState $l.Path ($root + $l.Rel)
            $size = [int64]0
            if ($state -eq 'realdir') { Write-Host "Measuring $($l.Path) ..."; $size = Get-DirSize $l.Path }
            $plan += [pscustomobject]@{ Key = $d.Key; Path = $l.Path; Rel = $l.Rel; State = $state; Size = $size }
        }
    }
    $total = [int64](($plan | Measure-Object -Property Size -Sum).Sum)
    Write-Host ('Data to move: {0:N1} GB' -f ($total / 1GB))

    # ---- vault
    if (-not (Test-Path -LiteralPath $vault)) {
        if ($VaultSize) { $sizeStr = $VaultSize.ToUpper() }
        else { $sizeStr = '{0}G' -f [int][math]::Max(5, [math]::Ceiling($total * 1.5 / 1GB) + 3) }
        $unit = 1GB; if ($sizeStr.EndsWith('M')) { $unit = 1MB }
        $sizeBytes = [int64]$sizeStr.Substring(0, $sizeStr.Length - 1) * $unit
        if ($sizeBytes -lt ($total + 1GB)) { throw "Vault size $sizeStr is too small for $([math]::Ceiling($total / 1GB)) GB of browser data." }
        $qual = Split-Path -Qualifier $vault
        $free = (New-Object IO.DriveInfo $qual).AvailableFreeSpace
        if ($sizeBytes + 1GB -gt $free) {
            throw ("Not enough free space on {0} for a {1} vault ({2:N1} GB free). Free up space or use -VaultPath on another drive." -f $qual, $sizeStr, ($free / 1GB))
        }
        New-Vault $vault $sizeStr $FileSystem $vc
    } else {
        Write-Host "Vault     : $vault (existing)"
    }

    Write-Host ''
    Write-Host 'Enter the password in the VeraCrypt window to open the vault.' -ForegroundColor Cyan
    if (-not (Open-Vault)) {
        throw ('The vault was not opened (cancelled or wrong password). Nothing was moved.' +
               ' If VeraCrypt showed a command-line error, run setup again with -NoSecureDesktop.')
    }

    # ---- move the data
    Write-Host ''
    $report = @()
    foreach ($item in $plan) {
        $target = $root + $item.Rel
        $status = ''
        try {
            Stop-Procs (Get-BrowserProcs)
            $state = Get-LinkState $item.Path $target
            switch ($state) {
                'ours' { $status = 'already protected' }
                'missing' {
                    [void][IO.Directory]::CreateDirectory($target)
                    New-Junction $item.Path $target
                    $status = 'protected (no data yet)'
                }
                'realdir' {
                    if ([IO.Directory]::Exists($target)) { [void](Remove-Tree $target) }   # leftover of an earlier failed try
                    $free = (New-Object IO.DriveInfo $drive).AvailableFreeSpace
                    if ($item.Size + 200MB -gt $free) { throw 'not enough space in the vault (enlarge it with VeraCrypt Expander)' }
                    Write-Host "Copying  $($item.Path)  ($('{0:N1}' -f ($item.Size / 1GB)) GB) ..."
                    if (-not (Copy-Verified $item.Path $target)) {
                        [void](Remove-Tree $target)
                        throw 'the copy could not be verified; nothing was changed'
                    }
                    $backup = $item.Path + '.sb-old'
                    if ([IO.Directory]::Exists($backup)) { $backup += '-' + (Get-Date -Format 'yyyyMMdd-HHmmss') }
                    try { [IO.Directory]::Move($item.Path, $backup) }
                    catch {
                        [void](Remove-Tree $target)
                        throw 'the folder is in use by another program; close it and run setup again'
                    }
                    try { New-Junction $item.Path $target }
                    catch { [IO.Directory]::Move($backup, $item.Path); throw }
                    $script:Cfg.Backups = @(Arr $Cfg.Backups) + $backup
                    $status = 'moved into the vault'
                }
                default { throw "unexpected item at this path ($state)" }
            }
            if (-not (@(Arr $Cfg.Links) | Where-Object { $_.Path -eq $item.Path })) {
                $script:Cfg.Links = @(Arr $Cfg.Links) + [pscustomobject]@{ Key = $item.Key; Path = $item.Path; Rel = $item.Rel }
            }
            Save-Config
            $report += [pscustomobject]@{ Ok = $true; Text = ('{0,-8} {1}  ->  {2}' -f $item.Key, $item.Path, $status) }
        } catch {
            $report += [pscustomobject]@{ Ok = $false; Text = ('{0,-8} {1}  ->  NOT protected: {2}' -f $item.Key, $item.Path, $_.Exception.Message) }
        }
    }

    # ---- tasks, shortcut, guard
    Write-Host ''
    Register-Tasks
    New-Shortcut $LockShortcut "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledScript`" -Action Lock" `
        "$env:SystemRoot\System32\shell32.dll,47"
    Write-Host 'Shortcut  : Lock Browsers (desktop)'
    New-Shortcut $UnlockShortcut "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledScript`" -Action Unlock" `
        "$vc,0"
    Write-Host 'Shortcut  : Unlock Browsers (desktop)'
    $n = Update-BrowserShortcuts
    Write-Host "Shortcuts : $n browser shortcut(s) now ask for the password"
    Start-Guard

    Write-Host ''
    Write-Host '=== Result ===' -ForegroundColor Cyan
    foreach ($r in $report) {
        if ($r.Ok) { Write-Host $r.Text -ForegroundColor Green } else { Write-Host $r.Text -ForegroundColor Red }
    }

    # ---- check, then remove the unprotected copies
    Write-Host ''
    Write-Host 'The vault is open now. Open each browser and check that bookmarks, saved passwords,' -ForegroundColor Yellow
    Write-Host 'logged-in sites, history and extensions are all there.' -ForegroundColor Yellow
    [void](Read-Host 'Press Enter when you have checked')
    $backups = @(Arr $Cfg.Backups)
    if ($backups.Count -gt 0) {
        Write-Host ''
        Write-Host 'These old copies are still on the disk WITHOUT protection:'
        $backups | ForEach-Object { Write-Host "  $_" }
        if ((Read-Host 'Everything OK? Delete the old copies now? (y/n)') -match '^[yY]') { Invoke-Cleanup }
        else { Write-Host "Delete them later with:  powershell -ExecutionPolicy Bypass -File `"$InstalledScript`" -Action Cleanup" }
    }

    Write-Host ''
    Write-Host 'Done. Test it: press Win+L, sign in again, then open any browser - it should ask for the password.' -ForegroundColor Green
    Write-Host "Vault file: $vault  (encrypted; keep a backup copy of this file)"
}

function Invoke-Cleanup {
    $left = @()
    foreach ($b in (Arr $Cfg.Backups)) {
        Write-Host "Deleting $b ..."
        if (Remove-Tree $b) { Write-Host '  deleted' -ForegroundColor Green }
        else { $left += $b; Write-Warning "  could not fully delete: $b" }
    }
    $script:Cfg.Backups = $left
    Save-Config
}

function Invoke-Uninstall {
    Write-Host 'This moves all browser data back to its original place and removes Secure Browser.' -ForegroundColor Cyan
    if ((Read-Host 'Continue? (y/n)') -notmatch '^[yY]') { return }
    Stop-Guard
    Disable-ScheduledTask -TaskName $LockTask -ErrorAction SilentlyContinue | Out-Null

    Write-Host 'Close ALL browser windows, then press Enter.' -ForegroundColor Yellow
    [void](Read-Host)
    Stop-Procs (Get-BrowserProcs)
    Write-Host 'Enter the password in the VeraCrypt window.'
    if (-not (Open-Vault)) {
        Enable-ScheduledTask -TaskName $LockTask -ErrorAction SilentlyContinue | Out-Null
        Start-Guard
        throw 'The vault was not opened. Nothing was changed.'
    }
    Stop-Procs (Get-BrowserProcs)

    $root = Get-Root
    $still = @()
    foreach ($l in (Arr $Cfg.Links)) {
        $target = $root + $l.Rel
        if ((Get-LinkState $l.Path $target) -ne 'ours') { Write-Warning "Skipped (not a Secure Browser link): $($l.Path)"; continue }
        Write-Host "Moving back: $($l.Path)"
        [IO.Directory]::Delete($l.Path)                       # removes only the link
        if (Copy-Verified $target $l.Path) {
            Write-Host '  OK' -ForegroundColor Green
        } else {
            [void](Remove-Tree $l.Path)
            New-Junction $l.Path $target
            $still += $l
            Write-Warning '  could not copy back; this one stays protected'
        }
    }
    if ($still.Count -gt 0) {
        $script:Cfg.Links = $still
        Save-Config
        Enable-ScheduledTask -TaskName $LockTask -ErrorAction SilentlyContinue | Out-Null
        Start-Guard
        Write-Warning 'Some folders could not be moved back (see above). Close all programs and run -Action Uninstall again.'
        return
    }

    Close-Vault
    Unregister-ScheduledTask -TaskName $LockTask -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $GuardTask -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $LockShortcut, $UnlockShortcut, $StartupShortcut -ErrorAction SilentlyContinue
    Restore-BrowserShortcuts
    Write-Host 'Browser shortcuts restored.'

    $backups = @(Arr $Cfg.Backups)
    if ($backups.Count -gt 0) {
        Write-Host 'Old copies from before setup (older than the data just restored):'
        $backups | ForEach-Object { Write-Host "  $_" }
        if ((Read-Host 'Delete them? (y/n)') -match '^[yY]') { foreach ($b in $backups) { [void](Remove-Tree $b) } }
    }
    Remove-Item -LiteralPath $ConfigPath, $RestorePath -ErrorAction SilentlyContinue
    if ($ThisScript -ne $InstalledScript) { Remove-Item -LiteralPath $InstalledScript -ErrorAction SilentlyContinue }

    Write-Host ''
    Write-Host 'Uninstalled. All browsers use their normal folders again.' -ForegroundColor Green
    Write-Host "After checking the browsers you can delete the vault file: $($Cfg.VaultPath)"
}

# =================================================================== main

if ($Action -eq 'Setup') {
    Invoke-Setup
    return
}

$Cfg = Read-Config
if (-not $Cfg) {
    if ($Interactive) { Write-Warning 'Secure Browser is not set up on this account.' }
    return
}
switch ($Action) {
    'Guard'     { Invoke-Guard }
    'Lock'      { Invoke-Lock }
    'Unlock'    { [void](Invoke-Unlock) }
    'Open'      { Invoke-Open }
    'Cleanup'   { Invoke-Cleanup }
    'Uninstall' { Invoke-Uninstall }
}
