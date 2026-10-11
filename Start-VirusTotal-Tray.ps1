# VirusTotal Tray. Left click opens the panel. The panel only draws JSON.
param(
    [switch]$SelfTest,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Dropped
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:root = $root
# Same split as Windows Agents: settings in Roaming, logs and history in Local.
$script:settingsDir = Join-Path $env:APPDATA "VirusTotal-Tray"
$script:dataDir = Join-Path $env:LOCALAPPDATA "VirusTotal-Tray"

function Ensure-Directory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function Write-Log([string]$Message) {
    if (-not $script:dataDir) { return }
    Ensure-Directory $script:dataDir
    $line = "{0}  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path (Join-Path $script:dataDir "tray.log") -Value $line -Encoding utf8
}

function Quote-Arg([string]$Value) {
    if ($null -eq $Value) { return '""' }
    return '"' + ($Value -replace '"', '\"') + '"'
}

if (-not $SelfTest -and [Threading.Thread]::CurrentThread.GetApartmentState() -ne "STA") {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append("-STA -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ")
    [void]$builder.Append((Quote-Arg $PSCommandPath))
    if ($Dropped) {
        foreach ($arg in $Dropped) {
            [void]$builder.Append(" ")
            [void]$builder.Append((Quote-Arg $arg))
        }
    }
    $psi.Arguments = $builder.ToString()
    [void][System.Diagnostics.Process]::Start($psi)
    exit 0
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.Web.Extensions
Add-Type -AssemblyName System.Security

$script:serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$script:serializer.MaxJsonLength = 8000000
$script:mb = 1MB

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class VtWindow {
    public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int x, int y, int w, int h, bool repaint);
    [DllImport("user32.dll")] public static extern bool DestroyIcon(IntPtr hIcon);
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct VtPropertyKey {
    public Guid fmtid;
    public uint pid;
}

[StructLayout(LayoutKind.Explicit)]
public struct VtPropVariant {
    [FieldOffset(0)] public ushort vt;
    [FieldOffset(8)] public IntPtr p;
    [FieldOffset(16)] public IntPtr pad;
}

[ComImport, Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IVtPropertyStore {
    [PreserveSig] int GetCount(out uint count);
    [PreserveSig] int GetAt(uint index, out VtPropertyKey key);
    [PreserveSig] int GetValue(ref VtPropertyKey key, out VtPropVariant value);
    [PreserveSig] int SetValue(ref VtPropertyKey key, ref VtPropVariant value);
    [PreserveSig] int Commit();
}

public static class VtShell {
    [DllImport("shell32.dll")]
    static extern int SHGetPropertyStoreForWindow(IntPtr hwnd, ref Guid iid, [MarshalAs(UnmanagedType.Interface)] out IVtPropertyStore store);

    static void SetString(IVtPropertyStore store, uint pid, string value) {
        VtPropertyKey key = new VtPropertyKey();
        key.fmtid = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3");
        key.pid = pid;
        VtPropVariant variant = new VtPropVariant();
        variant.vt = 31;
        variant.p = Marshal.StringToCoTaskMemUni(value);
        try { store.SetValue(ref key, ref variant); }
        finally { Marshal.FreeCoTaskMem(variant.p); }
    }

    public static bool SetAppIdentity(IntPtr hwnd, string appId, string relaunchCommand, string iconResource, string displayName) {
        Guid iid = new Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99");
        IVtPropertyStore store;
        if (SHGetPropertyStoreForWindow(hwnd, ref iid, out store) != 0 || store == null) return false;
        try {
            SetString(store, 2, relaunchCommand);
            SetString(store, 3, iconResource);
            SetString(store, 4, displayName);
            SetString(store, 5, appId);
            return store.Commit() == 0;
        } finally {
            Marshal.ReleaseComObject(store);
        }
    }
}
"@

Add-Type @"
using System;
using System.IO;
using System.Collections.Concurrent;
public sealed class VtDownloadWatch : IDisposable {
    public readonly ConcurrentQueue<string> Paths = new ConcurrentQueue<string>();
    FileSystemWatcher watcher;
    public void Start(string directory) {
        Stop();
        watcher = new FileSystemWatcher(directory, "*");
        watcher.IncludeSubdirectories = false;
        watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite;
        watcher.Created += OnCreated;
        watcher.Renamed += OnRenamed;
        watcher.EnableRaisingEvents = true;
    }
    void OnCreated(object sender, FileSystemEventArgs e) { Enqueue(e.FullPath); }
    void OnRenamed(object sender, RenamedEventArgs e) { Enqueue(e.FullPath); }
    void Enqueue(string path) {
        if (!string.IsNullOrEmpty(path)) Paths.Enqueue(path);
    }
    public void Stop() {
        if (watcher == null) return;
        watcher.EnableRaisingEvents = false;
        watcher.Dispose();
        watcher = null;
    }
    public void Dispose() { Stop(); }
}
"@

function ConvertTo-Hashtable($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return $Value
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $table = @{}
        foreach ($key in @($Value.Keys)) {
            $table[[string]$key] = ConvertTo-Hashtable $Value[$key]
        }
        return ,$table
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Value) { [void]$list.Add((ConvertTo-Hashtable $item)) }
        return ,$list
    }
    return $Value
}

function Write-Inbox([string[]]$Paths) {
    $clean = @($Paths | Where-Object { $_ })
    if ($clean.Count -eq 0) { return }
    $dir = Join-Path $script:dataDir "inbox"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $name = "{0}-{1}.list" -f (Get-Date -Format "yyyyMMddHHmmssfff"), ([guid]::NewGuid().ToString("N").Substring(0, 8))
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllLines((Join-Path $dir $name), $clean, $utf8)
}

function Read-Inbox {
    $dir = Join-Path $script:dataDir "inbox"
    if (-not (Test-Path -LiteralPath $dir)) { return }
    foreach ($file in @(Get-ChildItem -LiteralPath $dir -Filter *.list -ErrorAction SilentlyContinue)) {
        try {
            $lines = [System.IO.File]::ReadAllLines($file.FullName)
            Remove-Item -LiteralPath $file.FullName -Force
            foreach ($line in $lines) { Add-Queue $line }
            Show-Panel
        } catch {
            Write-Log $_.Exception.Message
        }
    }
}

function Get-SettingsPath { Join-Path $script:settingsDir "settings.json" }
function Get-HistoryPath { Join-Path $script:dataDir "history.json" }

function Get-KeyEntropy {
    return [Text.Encoding]::UTF8.GetBytes("VirusTotal-Tray")
}

function Protect-ApiKey([string]$Key) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Key)
    $protected = [Security.Cryptography.ProtectedData]::Protect(
        $bytes,
        (Get-KeyEntropy),
        [Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    return [Convert]::ToBase64String($protected)
}

function Unprotect-ApiKey([string]$Blob) {
    $raw = [Convert]::FromBase64String($Blob)
    try {
        $bytes = [Security.Cryptography.ProtectedData]::Unprotect(
            $raw,
            (Get-KeyEntropy),
            [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [Text.Encoding]::UTF8.GetString($bytes)
    } catch {
        $bytes = [Security.Cryptography.ProtectedData]::Unprotect(
            $raw,
            [Text.Encoding]::UTF8.GetBytes("VirusTotal-Hotbar"),
            [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        $key = [Text.Encoding]::UTF8.GetString($bytes)
        if ($key.Trim()) { Save-ApiKey $key.Trim() }
        return $key
    }
}

function Read-Flag($Obj, [string]$Name) {
    if ($null -eq $Obj -or $Obj -isnot [System.Collections.IDictionary]) { return $false }
    if (-not $Obj.ContainsKey($Name) -or $null -eq $Obj[$Name]) { return $false }
    return [System.Convert]::ToBoolean($Obj[$Name])
}

function Read-RawSettings {
    $raw = @{ apiKeyProtected = ""; apiKey = ""; watchDownloads = $false; notifyFlagged = $false }
    $path = Get-SettingsPath
    if (-not (Test-Path -LiteralPath $path)) { return $raw }
    try {
        $obj = $script:serializer.DeserializeObject([System.IO.File]::ReadAllText($path))
        if ($obj -and $obj["apiKeyProtected"]) { $raw["apiKeyProtected"] = [string]$obj["apiKeyProtected"] }
        if ($obj -and $obj["apiKey"]) { $raw["apiKey"] = [string]$obj["apiKey"] }
        $raw["watchDownloads"] = Read-Flag $obj "watchDownloads"
        $raw["notifyFlagged"] = Read-Flag $obj "notifyFlagged"
    } catch {
        Write-Log ("settings: " + $_.Exception.Message)
    }
    return $raw
}

function Write-RawSettings($Raw) {
    Ensure-Directory $script:settingsDir
    $payload = @{
        apiKeyProtected = [string]$Raw["apiKeyProtected"]
        watchDownloads = [bool]$Raw["watchDownloads"]
        notifyFlagged = [bool]$Raw["notifyFlagged"]
    }
    $json = ConvertTo-Json -InputObject $payload -Compress
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText((Get-SettingsPath), $json, $utf8)
}

function Read-Settings {
    $raw = Read-RawSettings
    $key = ""
    if ($raw["apiKeyProtected"]) {
        try {
            $key = (Unprotect-ApiKey ([string]$raw["apiKeyProtected"])).Trim()
        } catch {
            Write-Log "settings: the saved API key could not be decrypted for this Windows user"
            $script:notice = "The saved API key could not be opened for this Windows user. Enter it again."
        }
    } elseif ($raw["apiKey"]) {
        $key = ([string]$raw["apiKey"]).Trim()
        if ($key) { Save-ApiKey $key }
    }
    return ,@{
        apiKey = $key
        watchDownloads = [bool]$raw["watchDownloads"]
        notifyFlagged = [bool]$raw["notifyFlagged"]
    }
}

function Get-ApiKey { return [string](Read-Settings).apiKey }

function Save-ApiKey([string]$Key) {
    $raw = Read-RawSettings
    $raw["apiKeyProtected"] = Protect-ApiKey $Key.Trim()
    $raw["apiKey"] = ""
    Write-RawSettings $raw
}

function Save-History {
    if ($script:scans.Count -eq 0) { $json = "[]" }
    else { $json = ConvertTo-Json -InputObject $script:scans -Depth 8 -Compress }
    Ensure-Directory $script:dataDir
    $utf8 = New-Object System.Text.UTF8Encoding $false
    $path = Get-HistoryPath
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllText($tmp, $json, $utf8)
    Move-Item -LiteralPath $tmp -Destination $path -Force
}

function Load-History {
    $script:scans = New-Object System.Collections.Generic.List[object]
    $path = Get-HistoryPath
    if (-not (Test-Path -LiteralPath $path)) { return }
    try {
        $loaded = ConvertTo-Hashtable ($script:serializer.DeserializeObject([System.IO.File]::ReadAllText($path)))
        foreach ($item in $loaded) {
            if ($item -isnot [System.Collections.IDictionary]) { continue }
            if (-not $item["id"] -and $item["sha256"]) { $item["id"] = [string]$item["sha256"] }
            if (-not $item["id"]) { continue }
            if (-not $item["kind"]) { $item["kind"] = "file" }
            if ($item["status"] -in @("hashing", "checking", "uploading")) {
                $item["status"] = "error"
                $item["error"] = "Interrupted. Scan the file again."
            }
            if ([string]$item["phase"] -eq "queued") {
                $item["status"] = "completed"
                $item["phase"] = ""
                $item["analysisId"] = ""
            }
            if ($item["stats"] -isnot [System.Collections.IDictionary]) {
                $item["stats"] = @{ malicious = 0; suspicious = 0; undetected = 0; harmless = 0; timeout = 0; failure = 0 }
            }
            $script:scans.Add($item)
        }
    } catch {
        Write-Log ("history: " + $_.Exception.Message)
    }
}

function Publish-Data {
    Sync-Activity
    $payload = @{
        updatedAt = (Get-Date).ToString("o")
        apiKeySet = -not [string]::IsNullOrWhiteSpace((Get-ApiKey))
        activity = [string]$script:activity
        notice = [string]$script:notice
        watchDownloads = [bool]$script:watchDownloads
        notifyFlagged = [bool]$script:notifyFlagged
        scans = $script:scans
    }
    $json = ConvertTo-Json -InputObject $payload -Depth 8 -Compress
    $body = "window.VT_DATA = $json;`n"
    $dir = Join-Path $script:root "panel"
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $path = Join-Path $dir "data.js"
    $tmp = "$path.tmp"
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($tmp, $body, $utf8)
    Move-Item -LiteralPath $tmp -Destination $path -Force
    try { Save-History } catch { Write-Log ("save: " + $_.Exception.Message) }
    Update-Tooltip
}

function Sync-Activity {
    $active = @($script:scans | Where-Object { $_["status"] -in @("hashing", "checking", "uploading", "scanning") })
    if ($active.Count -eq 0) {
        if ($script:activity -match '^(Hashing|Checking|Uploading|Scanning|Queued) ') { $script:activity = "" }
        return
    }
    $current = $active[0]
    $verb = switch ([string]$current["status"]) {
        "hashing" { "Hashing" }
        "checking" { "Checking" }
        "uploading" { "Uploading" }
        default { "Scanning" }
    }
    if ([string]$current["status"] -eq "scanning" -and [string]$current["phase"] -eq "queued") { $verb = "Queued" }
    $script:activity = "$verb $($current["name"])"
}

function Send-Command([string]$Action) {
    $script:commandSeq += 1
    $path = Join-Path $script:root "panel\command.js"
    $body = "window.VT_COMMAND = { seq: $($script:commandSeq), action: `"$Action`" };`n"
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($path, $body, $utf8)
}

function Send-Idle { Send-Command "idle" }

function Get-ScanKey($Scan) {
    if ($Scan["id"]) { return [string]$Scan["id"] }
    return [string]$Scan["sha256"]
}

function Add-Scan($Scan) {
    $key = Get-ScanKey $Scan
    for ($i = $script:scans.Count - 1; $i -ge 0; $i--) {
        if ((Get-ScanKey $script:scans[$i]) -eq $key) { $script:scans.RemoveAt($i) }
    }
    $script:scans.Insert(0, $Scan)
    while ($script:scans.Count -gt 40) { $script:scans.RemoveAt($script:scans.Count - 1) }
}

function Add-Queue([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($script:queue.Contains($full)) { return }
    [void]$script:queue.Add($full)
}

function Test-DownloadCandidate([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $name = [System.IO.Path]::GetFileName($Path)
    if ([string]::IsNullOrWhiteSpace($name)) { return $false }
    if ($name -match '^(?i)desktop\.ini$') { return $false }
    if ($name -match '^(?i)thumbs\.db$') { return $false }
    if ($name -match '(?i)\.(crdownload|tmp|part|partial|download|opdownload|fdmdownload)$') { return $false }
    return $true
}

function Get-DownloadsFolder {
    try {
        $shell = New-Object -ComObject Shell.Application
        $folder = $shell.NameSpace("shell:Downloads")
        if ($folder -and $folder.Self -and $folder.Self.Path -and (Test-Path -LiteralPath $folder.Self.Path)) {
            return [string]$folder.Self.Path
        }
    } catch {}
    $fallback = Join-Path $env:USERPROFILE "Downloads"
    if (Test-Path -LiteralPath $fallback) { return $fallback }
    return ""
}

function Save-WatchSettings([bool]$Watch, [bool]$Notify) {
    $raw = Read-RawSettings
    $raw["watchDownloads"] = $Watch
    $raw["notifyFlagged"] = $Notify
    Write-RawSettings $raw
    $script:watchDownloads = $Watch
    $script:notifyFlagged = $Notify
    Update-DownloadWatch
    Publish-Data
}

function Import-WatchSettings {
    $raw = Read-RawSettings
    $script:watchDownloads = [bool]$raw["watchDownloads"]
    $script:notifyFlagged = [bool]$raw["notifyFlagged"]
    Update-DownloadWatch
}

function Update-DownloadWatch {
    if ($script:downloadWatch) { $script:downloadWatch.Stop() }
    if ($SelfTest -or -not $script:watchDownloads) { return }
    $dir = Get-DownloadsFolder
    if (-not $dir) {
        $script:notice = "The Downloads folder could not be found."
        return
    }
    if (-not $script:downloadWatch) { $script:downloadWatch = New-Object VtDownloadWatch }
    $script:downloadWatch.Start($dir)
}

function Settle-Downloads {
    if (-not $script:watchDownloads -or -not $script:downloadWatch) { return }
    if (((Get-Date) - $script:downloadCheck).TotalSeconds -lt 1) { return }
    $script:downloadCheck = Get-Date
    $path = ""
    while ($script:downloadWatch.Paths.TryDequeue([ref]$path)) {
        if (-not (Test-DownloadCandidate $path)) { continue }
        try { $path = [System.IO.Path]::GetFullPath($path) } catch { continue }
        $key = $path.ToLowerInvariant()
        if ($script:downloadSeen.ContainsKey($key)) { continue }
        if (-not $script:downloadPending.ContainsKey($key)) {
            $script:downloadPending[$key] = @{ Path = $path; Size = [int64]-1; Stable = 0 }
        }
    }
    $ready = @()
    foreach ($key in @($script:downloadPending.Keys)) {
        $entry = $script:downloadPending[$key]
        $file = [string]$entry.Path
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            $script:downloadPending.Remove($key)
            continue
        }
        try {
            $size = [int64](Get-Item -LiteralPath $file).Length
            if ($size -gt 0 -and $size -eq [int64]$entry.Size) { $entry.Stable += 1 }
            else { $entry.Size = $size; $entry.Stable = 0 }
            if ($entry.Stable -ge 1) { $ready += $key }
        } catch {}
    }
    foreach ($key in $ready) {
        $file = [string]$script:downloadPending[$key].Path
        $script:downloadPending.Remove($key)
        $script:downloadSeen[$key] = $true
        $script:watchedPaths[$key] = $true
        Add-Queue $file
    }
}

function New-EmptyStats {
    return ,@{ malicious = 0; suspicious = 0; undetected = 0; harmless = 0; timeout = 0; failure = 0 }
}

function Get-StatTotal($Stats) {
    if (-not $Stats) { return 0 }
    $sum = 0
    foreach ($name in @("malicious", "suspicious", "undetected", "harmless", "timeout", "failure")) {
        $value = 0
        if ($Stats -is [System.Collections.IDictionary]) {
            if ($null -ne $Stats[$name]) { $value = $Stats[$name] }
        } else {
            $prop = $Stats.PSObject.Properties[$name]
            if ($prop) { $value = $prop.Value }
        }
        $sum += [int]$value
    }
    return $sum
}

function Get-Stats($Stats) {
    $out = New-EmptyStats
    if (-not $Stats) { return ,$out }
    foreach ($name in @("malicious", "suspicious", "undetected", "harmless", "timeout", "failure")) {
        $prop = $Stats.PSObject.Properties[$name]
        if ($prop) { $out[$name] = [int]$prop.Value }
    }
    return ,$out
}

function Get-Hits($Results) {
    $hits = New-Object System.Collections.Generic.List[object]
    if (-not $Results) { return ,$hits }
    foreach ($prop in @($Results.PSObject.Properties)) {
        $value = $prop.Value
        if (-not $value) { continue }
        $category = [string]$value.category
        if ($category -ne "malicious" -and $category -ne "suspicious") { continue }
        $hits.Add(@{
            engine = [string]$value.engine_name
            category = $category
            result = [string]$value.result
        })
    }
    $ranked = @($hits | Sort-Object @{ Expression = { if ($_["category"] -eq "malicious") { 0 } else { 1 } } }, @{ Expression = { $_["engine"] } })
    $trimmed = New-Object System.Collections.Generic.List[object]
    $count = 0
    foreach ($hit in $ranked) {
        $trimmed.Add($hit)
        $count += 1
        if ($count -ge 12) { break }
    }
    return ,$trimmed
}

function Get-ThreatLabel($Attrs) {
    if (-not $Attrs) { return "" }
    $classification = $Attrs.popular_threat_classification
    if ($classification -and $classification.suggested_threat_label) {
        return [string]$classification.suggested_threat_label
    }
    return ""
}

function Update-ScanFromFile($Scan, $Data) {
    $attrs = $Data.attributes
    if (-not $attrs) { return }
    $Scan["stats"] = Get-Stats $attrs.last_analysis_stats
    $Scan["hits"] = Get-Hits $attrs.last_analysis_results
    $Scan["typeDescription"] = [string]$attrs.type_description
    $Scan["threatLabel"] = Get-ThreatLabel $attrs
    if ($attrs.size) { $Scan["size"] = [int64]$attrs.size }
    $Scan["status"] = "completed"
    $Scan["phase"] = ""
    $Scan["error"] = ""
}

function Update-ScanFromAnalysis($Scan, $Root) {
    if (-not $Root -or -not $Root.data) { return }
    $attrs = $Root.data.attributes
    if (-not $attrs) { return }
    if ([string]$attrs.status -eq "completed") {
        if ($attrs.stats) { $Scan["stats"] = Get-Stats $attrs.stats }
        if ($attrs.results) { $Scan["hits"] = Get-Hits $attrs.results }
        $Scan["status"] = "completed"
        $Scan["phase"] = ""
        $Scan["error"] = ""
        return
    }
    $incoming = $null
    if ($attrs.stats) { $incoming = Get-Stats $attrs.stats }
    if ($incoming -and (Get-StatTotal $incoming) -gt 0) {
        $Scan["stats"] = $incoming
        if ($attrs.results) { $Scan["hits"] = Get-Hits $attrs.results }
        $Scan["phase"] = "running"
    }
    $Scan["status"] = "scanning"
}

function Get-ApiError($Body, [int]$Status) {
    try {
        if ($Body) {
            $obj = $Body | ConvertFrom-Json
            if ($obj.error.message) { return [string]$obj.error.message }
        }
    } catch {}
    if ($Status -eq 401 -or $Status -eq 403) { return "API key was rejected." }
    if ($Status -eq 404) { return "Not found" }
    if ($Status -eq 429) { return "VirusTotal rate limit. Wait a minute and scan again." }
    return "VirusTotal returned $Status."
}

function Test-VtUploadUrl([string]$Url) {
    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri)) { return $false }
    if ($uri.UserInfo) { return $false }
    $scheme = $uri.Scheme.ToLowerInvariant()
    if ($scheme -ne "https" -and $scheme -ne "http") { return $false }
    $hostName = $uri.IdnHost.ToLowerInvariant()
    return ($hostName -eq "virustotal.com" -or $hostName.EndsWith(".virustotal.com"))
}

function Wait-Task($Task) {
    while (-not $Task.Wait(40)) {
        [System.Windows.Forms.Application]::DoEvents()
    }
    if ($Task.IsFaulted) {
        $errorRecord = $Task.Exception
        if ($errorRecord.InnerException) { throw $errorRecord.InnerException }
        throw $errorRecord
    }
    return $Task.Result
}

function Invoke-Vt {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [string]$FilePath,
        [string]$FormBody
    )
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [TimeSpan]::FromMinutes(20)
    [void]$client.DefaultRequestHeaders.TryAddWithoutValidation("x-apikey", $ApiKey)
    [void]$client.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "application/json")
    $request = New-Object System.Net.Http.HttpRequestMessage ((New-Object System.Net.Http.HttpMethod $Method), $Url)
    $stream = $null
    try {
        if ($FilePath) {
            $stream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $fileContent = New-Object System.Net.Http.StreamContent $stream
            [void]$fileContent.Headers.TryAddWithoutValidation("Content-Type", "application/octet-stream")
            $multipart = New-Object System.Net.Http.MultipartFormDataContent
            $multipart.Add($fileContent, "file", [System.IO.Path]::GetFileName($FilePath))
            $request.Content = $multipart
        } elseif ($FormBody) {
            $request.Content = New-Object System.Net.Http.StringContent -ArgumentList $FormBody, ([Text.Encoding]::UTF8), "application/x-www-form-urlencoded"
        }
        $response = Wait-Task ($client.SendAsync($request))
        try {
            $body = [string](Wait-Task ($response.Content.ReadAsStringAsync()))
            return ,@{ Status = [int]$response.StatusCode; Body = $body }
        } finally {
            $response.Dispose()
        }
    } finally {
        $request.Dispose()
        if ($stream) { $stream.Dispose() }
        $client.Dispose()
    }
}

function Get-FileSha256([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $buffer = New-Object byte[] (1MB)
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            [void]$sha.TransformBlock($buffer, 0, $read, $null, 0)
            [System.Windows.Forms.Application]::DoEvents()
        }
        [void]$sha.TransformFinalBlock(@(), 0, 0)
        return ([BitConverter]::ToString($sha.Hash)).Replace("-", "").ToLowerInvariant()
    } finally {
        $stream.Dispose()
        $sha.Dispose()
    }
}

function Fail-Scan($Scan, [string]$Message) {
    $Scan["status"] = "error"
    $Scan["error"] = $Message
    $script:activity = ""
    if ($Message -eq "API key was rejected.") { $script:notice = $Message }
    Publish-Data
    try {
        if ($script:notify) {
            $script:notify.ShowBalloonTip(5000, "VirusTotal Tray", ("{0} - {1}" -f $Scan["name"], $Message), [System.Windows.Forms.ToolTipIcon]::Warning)
        }
    } catch {}
}

function Notify-Verdict($Scan) {
    if ($Scan["status"] -ne "completed") { return }
    $watched = $false
    if ($Scan["watched"]) { $watched = [bool]$Scan["watched"] }
    if ($watched -and -not $script:notifyFlagged) { return }
    $malicious = 0
    $suspicious = 0
    if ($Scan["stats"]) {
        $malicious = [int]$Scan["stats"]["malicious"]
        $suspicious = [int]$Scan["stats"]["suspicious"]
    }
    if ($watched) {
        if ($malicious -le 0 -and $suspicious -le 0) { return }
    } elseif ($malicious -le 0) {
        return
    }
    $text = "{0} - {1} engines flagged" -f $Scan["name"], $malicious
    if ($malicious -le 0) { $text = "{0} - flagged as suspicious" -f $Scan["name"] }
    try {
        if ($script:notify) {
            $script:notify.ShowBalloonTip(6000, "VirusTotal Tray", $text, [System.Windows.Forms.ToolTipIcon]::Warning)
        }
    } catch {}
}

function New-Scan([string]$Path, [string]$Sha) {
    $item = Get-Item -LiteralPath $Path
    $hits = New-Object System.Collections.Generic.List[object]
    return ,@{
        id = $Sha
        kind = "file"
        name = $item.Name
        path = $item.FullName
        sha256 = $Sha
        size = [int64]$item.Length
        typeDescription = ""
        threatLabel = ""
        status = "checking"
        source = ""
        error = ""
        scannedAt = (Get-Date).ToString("o")
        analysisId = ""
        watched = ($script:watchedPaths.ContainsKey($item.FullName.ToLowerInvariant()))
        stats = (New-EmptyStats)
        hits = $hits
    }
}

function Get-StringSha256([string]$Text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
        return ([BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function ConvertTo-Indicator([string]$Text) {
    $value = ""
    if ($Text) { $value = $Text.Trim() }
    if (-not $value -or $value.Length -gt 2048) { return $null }
    if ($value -match '^(?i)https?://') {
        $uri = $null
        if (-not [Uri]::TryCreate($value, [UriKind]::Absolute, [ref]$uri)) { return $null }
        $scheme = $uri.Scheme.ToLowerInvariant()
        if ($scheme -ne "http" -and $scheme -ne "https") { return $null }
        return ,@{ kind = "url"; value = $uri.AbsoluteUri }
    }
    $parsedIp = $null
    $ipv4 = $value -match '^\d{1,3}(\.\d{1,3}){3}$'
    $ipv6 = $value.Contains(":")
    if (($ipv4 -or $ipv6) -and [Net.IPAddress]::TryParse($value, [ref]$parsedIp)) {
        if ($ipv4) {
            foreach ($octet in $value.Split(".")) {
                if ([int]$octet -gt 255) { return $null }
            }
        }
        return ,@{ kind = "ip"; value = $parsedIp.ToString() }
    }
    if ($value -notmatch '\s' -and $value.Contains(".")) {
        $uri = $null
        if ([Uri]::TryCreate("https://$value", [UriKind]::Absolute, [ref]$uri) -and $uri.Host.Contains(".")) {
            return ,@{ kind = "url"; value = $uri.AbsoluteUri }
        }
    }
    return $null
}

function Update-ScanFromReport($Scan, $Data) {
    Update-ScanFromFile $Scan $Data
    $attrs = $null
    if ($Data) { $attrs = $Data.attributes }
    if ($Scan["kind"] -eq "url") { $Scan["typeDescription"] = "URL" }
    if ($Scan["kind"] -eq "ip" -and $attrs) {
        $bits = New-Object System.Collections.Generic.List[string]
        [void]$bits.Add("IP address")
        if ($attrs.country) { [void]$bits.Add([string]$attrs.country) }
        if ($attrs.as_owner) { [void]$bits.Add([string]$attrs.as_owner) }
        $Scan["typeDescription"] = ($bits -join " - ")
    }
}

function Find-Scan([string]$Id) {
    foreach ($item in $script:scans) {
        if ((Get-ScanKey $item) -eq $Id) { return $item }
    }
    return $null
}

function Submit-Indicator([string]$Text) {
    $indicator = ConvertTo-Indicator $Text
    if (-not $indicator) {
        if ($script:notify) {
            $script:notify.ShowBalloonTip(4000, "VirusTotal Tray", "Enter a URL or an IP address.", [System.Windows.Forms.ToolTipIcon]::Info)
        }
        return
    }
    $kind = [string]$indicator["kind"]
    $value = [string]$indicator["value"]
    $id = $value
    $sha = ""
    if ($kind -eq "url") { $sha = Get-StringSha256 $value; $id = $sha }
    $short = $value
    if ($short.Length -gt 64) { $short = $short.Substring(0, 61) + "..." }
    $hits = New-Object System.Collections.Generic.List[object]
    $scan = @{
        id = $id
        kind = $kind
        name = $short
        path = $(if ($kind -eq "url") { $value } else { "" })
        sha256 = $sha
        size = $null
        typeDescription = $(if ($kind -eq "url") { "URL" } else { "IP address" })
        threatLabel = ""
        status = "checking"
        source = ""
        error = ""
        scannedAt = (Get-Date).ToString("o")
        analysisId = ""
        stats = (New-EmptyStats)
        hits = $hits
    }
    Add-Scan $scan
    $script:activity = "Checking $short"
    Publish-Data
    $key = Get-ApiKey
    if (-not $key) {
        Fail-Scan $scan "Add a VirusTotal API key first."
        return
    }
    try {
        $lookupUrl = "https://www.virustotal.com/api/v3/ip_addresses/$value"
        if ($kind -eq "url") { $lookupUrl = "https://www.virustotal.com/api/v3/urls/$sha" }
        $lookup = Invoke-Vt -Method GET -Url $lookupUrl -ApiKey $key
        if ($lookup.Status -eq 200) {
            Update-ScanFromReport $scan (($lookup.Body | ConvertFrom-Json).data)
            $scan["source"] = "known"
            $script:notice = ""
            $script:activity = ""
            Publish-Data
            Notify-Verdict $scan
            return
        }
        if ($lookup.Status -ne 404) {
            $message = Get-ApiError $lookup.Body $lookup.Status
            if ($lookup.Status -eq 401 -or $lookup.Status -eq 403) { $script:notice = "API key was rejected." }
            Fail-Scan $scan $message
            return
        }
        $scan["status"] = "scanning"
        $script:activity = "Scanning $short"
        Publish-Data
        if ($kind -eq "url") {
            $body = "url=" + [Uri]::EscapeDataString($value)
            $sent = Invoke-Vt -Method POST -Url "https://www.virustotal.com/api/v3/urls" -ApiKey $key -FormBody $body
            $scan["source"] = "submitted"
        } else {
            $sent = Invoke-Vt -Method POST -Url "https://www.virustotal.com/api/v3/ip_addresses/$value/analyse" -ApiKey $key
            $scan["source"] = "submitted"
        }
        if ($sent.Status -ne 200) {
            $message = Get-ApiError $sent.Body $sent.Status
            if ($sent.Status -eq 401 -or $sent.Status -eq 403) { $script:notice = "API key was rejected." }
            Fail-Scan $scan $message
            return
        }
        $analysis = $sent.Body | ConvertFrom-Json
        $scan["analysisId"] = [string]$analysis.data.id
        $script:notice = ""
        Publish-Data
    } catch {
        Fail-Scan $scan $_.Exception.Message
        Write-Log $_.Exception.Message
    }
}

function Submit-File([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $item = Get-Item -LiteralPath $Path
    $name = $item.Name
    $length = [int64]$item.Length
    if ($length -gt (650 * $script:mb)) {
        $scan = New-Scan $Path ("too-large-" + [guid]::NewGuid().ToString("N"))
        $scan["sha256"] = $scan["id"]
        Add-Scan $scan
        Fail-Scan $scan "VirusTotal accepts files up to 650 MB."
        return
    }
    if ($length -gt (200 * $script:mb)) {
        $answer = [System.Windows.Forms.MessageBox]::Show(
            "Files over 200 MB often scan poorly. Upload $name anyway?",
            "VirusTotal Tray",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    }

    $script:activity = "Hashing $name"
    Publish-Data
    $sha = Get-FileSha256 $item.FullName
    $scan = New-Scan $item.FullName $sha
    Add-Scan $scan
    $script:activity = "Checking $name"
    Publish-Data

    $key = Get-ApiKey
    if (-not $key) {
        Fail-Scan $scan "Add a VirusTotal API key first."
        return
    }

    try {
        $lookup = Invoke-Vt -Method GET -Url "https://www.virustotal.com/api/v3/files/$sha" -ApiKey $key
        if ($lookup.Status -eq 200) {
            $parsed = $lookup.Body | ConvertFrom-Json
            Update-ScanFromFile $scan $parsed.data
            $scan["source"] = "known"
            $script:notice = ""
            $script:activity = ""
            Publish-Data
            Notify-Verdict $scan
            return
        }
        if ($lookup.Status -ne 404) {
            $message = Get-ApiError $lookup.Body $lookup.Status
            if ($lookup.Status -eq 401 -or $lookup.Status -eq 403) { $script:notice = "API key was rejected." }
            Fail-Scan $scan $message
            return
        }

        $uploadUrl = "https://www.virustotal.com/api/v3/files"
        if ($length -gt (32 * $script:mb)) {
            $script:activity = "Preparing upload for $name"
            Publish-Data
            $gate = Invoke-Vt -Method GET -Url "https://www.virustotal.com/api/v3/files/upload_url" -ApiKey $key
            if ($gate.Status -ne 200) {
                Fail-Scan $scan (Get-ApiError $gate.Body $gate.Status)
                return
            }
            $uploadUrl = [string](($gate.Body | ConvertFrom-Json).data)
            if (-not (Test-VtUploadUrl $uploadUrl)) {
                Fail-Scan $scan "VirusTotal returned an unexpected upload URL."
                return
            }
        }

        $scan["status"] = "uploading"
        $script:activity = "Uploading $name"
        Publish-Data
        $sent = Invoke-Vt -Method POST -Url $uploadUrl -ApiKey $key -FilePath $item.FullName
        if ($sent.Status -ne 200) {
            $message = Get-ApiError $sent.Body $sent.Status
            if ($sent.Status -eq 401 -or $sent.Status -eq 403) { $script:notice = "API key was rejected." }
            Fail-Scan $scan $message
            return
        }
        $analysis = $sent.Body | ConvertFrom-Json
        $scan["analysisId"] = [string]$analysis.data.id
        $scan["status"] = "scanning"
        $scan["source"] = "uploaded"
        $script:notice = ""
        $script:activity = "Scanning $name"
        Publish-Data
    } catch {
        Fail-Scan $scan $_.Exception.Message
        Write-Log $_.Exception.Message
    }
}

function Invoke-Rescan([string]$Id) {
    $scan = Find-Scan $Id
    if (-not $scan) { return }
    $key = Get-ApiKey
    if (-not $key) {
        $script:notice = "Add a VirusTotal API key first."
        Publish-Data
        return
    }
    $scan["status"] = "scanning"
    $scan["phase"] = ""
    $scan["source"] = "rescan"
    $scan["error"] = ""
    $scan["scannedAt"] = (Get-Date).ToString("o")
    Add-Scan $scan
    Publish-Data
    $kind = [string]$scan["kind"]
    if (-not $kind) { $kind = "file" }
    $endpoint = "https://www.virustotal.com/api/v3/files/$($scan["sha256"])/analyse"
    if ($kind -eq "url") { $endpoint = "https://www.virustotal.com/api/v3/urls/$($scan["sha256"])/analyse" }
    elseif ($kind -eq "ip") { $endpoint = "https://www.virustotal.com/api/v3/ip_addresses/$($scan["id"])/analyse" }
    try {
        $sent = Invoke-Vt -Method POST -Url $endpoint -ApiKey $key
        if ($sent.Status -ne 200) {
            $message = Get-ApiError $sent.Body $sent.Status
            if ($sent.Status -eq 401 -or $sent.Status -eq 403) { $script:notice = "API key was rejected." }
            Fail-Scan $scan $message
            return
        }
        $analysis = $sent.Body | ConvertFrom-Json
        $scan["analysisId"] = [string]$analysis.data.id
        $encoded = [Uri]::EscapeDataString([string]$scan["analysisId"])
        $look = Invoke-Vt -Method GET -Url "https://www.virustotal.com/api/v3/analyses/$encoded" -ApiKey $key
        if ($look.Status -eq 200) {
            Update-ScanFromAnalysis $scan ($look.Body | ConvertFrom-Json)
        }
        if ([string]$scan["status"] -ne "completed") {
            $scan["status"] = "completed"
            $scan["phase"] = ""
            $scan["analysisId"] = ""
            $script:notice = "VirusTotal has not started the rescan. Showing the previous report."
        } else {
            $script:notice = ""
            Notify-Verdict $scan
        }
        Publish-Data
    } catch {
        Fail-Scan $scan $_.Exception.Message
        Write-Log $_.Exception.Message
    }
}

function Poll-Analyses {
    $pending = @($script:scans | Where-Object { $_["status"] -eq "scanning" -and $_["analysisId"] })
    if ($pending.Count -eq 0) { return }
    if (((Get-Date) - $script:lastPoll).TotalSeconds -lt 20) { return }
    $key = Get-ApiKey
    if (-not $key) { return }
    $script:lastPoll = Get-Date
    $script:pollIndex = $script:pollIndex + 1
    $scan = $pending[$script:pollIndex % $pending.Count]
    $script:busy = $true
    try {
        if ([string]$scan["phase"] -eq "queued") {
            $scan["status"] = "completed"
            $scan["phase"] = ""
            $scan["analysisId"] = ""
            $script:notice = "VirusTotal has not started the rescan. Showing the previous report."
            Publish-Data
            return
        }
        $encoded = [Uri]::EscapeDataString([string]$scan["analysisId"])
        $result = Invoke-Vt -Method GET -Url "https://www.virustotal.com/api/v3/analyses/$encoded" -ApiKey $key
        if ($result.Status -ne 200) {
            if ($result.Status -eq 401 -or $result.Status -eq 403) { $script:notice = "API key was rejected."; Publish-Data }
            return
        }
        $was = [string]$scan["status"]
        Update-ScanFromAnalysis $scan ($result.Body | ConvertFrom-Json)
        $script:notice = ""
        Publish-Data
        if ($scan["status"] -eq "completed" -and $was -ne "completed") { Notify-Verdict $scan }
    } catch {
        Write-Log $_.Exception.Message
    } finally {
        $script:busy = $false
        Drain-AfterBusy
    }
}

function Process-Next {
    if ($script:busy -or $script:queue.Count -eq 0) { return }
    $path = $script:queue[0]
    $script:queue.RemoveAt(0)
    $script:busy = $true
    try { Submit-File $path }
    finally { Complete-Busy }
}

function Submit-QueuedUrl([string]$Value) {
    if ($script:busy) {
        $script:afterBusy = "url:" + $Value
        return
    }
    $script:busy = $true
    try {
        if (-not (Get-ApiKey)) {
            if (-not (Show-KeyForm)) { return }
        }
        Submit-Indicator $Value
    } finally { Complete-Busy }
}

function Focus-Indicator {
    Show-Panel
    Send-Command "focus"
}

function Drain-AfterBusy {
    if ($script:busy) { return }
    $next = [string]$script:afterBusy
    if (-not $next) { return }
    $script:afterBusy = ""
    if ($next -eq "pick") { Show-FileDialog }
    elseif ($next -eq "key") { Show-KeyDialog }
    elseif ($next -eq "indicator") { Focus-Indicator }
    elseif ($next.StartsWith("url:")) { Submit-QueuedUrl $next.Substring(4) }
    elseif ($next.StartsWith("rescan:")) { Start-Rescan $next.Substring(7) }
}

function Complete-Busy {
    $script:busy = $false
    Send-Idle
    Drain-AfterBusy
}

function Show-KeyForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "VirusTotal API key"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    $form.ClientSize = New-Object System.Drawing.Size 400, 176
    $form.BackColor = [System.Drawing.Color]::FromArgb(255, 14, 20, 40)
    $form.ForeColor = [System.Drawing.Color]::FromArgb(255, 231, 237, 255)
    $form.Font = New-Object System.Drawing.Font "Segoe UI", 9

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Windows encrypts the key for this user account and saves it in AppData. Files you upload are shared with the VirusTotal community."
    $label.AutoSize = $false
    $label.Bounds = New-Object System.Drawing.Rectangle 16, 14, 368, 52
    $label.ForeColor = [System.Drawing.Color]::FromArgb(255, 142, 156, 192)

    $box = New-Object System.Windows.Forms.TextBox
    $box.Bounds = New-Object System.Drawing.Rectangle 16, 70, 368, 24
    $box.UseSystemPasswordChar = $true
    $existing = Get-ApiKey
    if ($existing) { $box.Text = $existing }

    $link = New-Object System.Windows.Forms.LinkLabel
    $link.Text = "Get a key"
    $link.Bounds = New-Object System.Drawing.Rectangle 16, 104, 120, 20
    $link.LinkColor = [System.Drawing.Color]::FromArgb(255, 92, 124, 255)
    $link.ActiveLinkColor = [System.Drawing.Color]::FromArgb(255, 231, 237, 255)
    $link.add_LinkClicked({ Start-Process "https://www.virustotal.com/gui/my-apikey" })

    $save = New-Object System.Windows.Forms.Button
    $save.Text = "Save"
    $save.Bounds = New-Object System.Drawing.Rectangle 292, 136, 92, 28
    $save.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $save

    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = "Cancel"
    $cancel.Bounds = New-Object System.Drawing.Rectangle 192, 136, 92, 28
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancel

    [void]$form.Controls.Add($label)
    [void]$form.Controls.Add($box)
    [void]$form.Controls.Add($link)
    [void]$form.Controls.Add($save)
    [void]$form.Controls.Add($cancel)
    $result = $form.ShowDialog()
    $saved = $false
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $key = $box.Text.Trim()
        if ($key) {
            Save-ApiKey $key
            $script:notice = ""
            $saved = $true
        }
    }
    $form.Dispose()
    return $saved
}

function Show-KeyDialog {
    if ($script:busy) { $script:afterBusy = "key"; return }
    $script:busy = $true
    try { [void](Show-KeyForm) }
    finally { Complete-Busy }
}

function Show-FileDialog {
    if ($script:busy) { $script:afterBusy = "pick"; return }
    $script:busy = $true
    try {
        if (-not (Get-ApiKey)) {
            if (-not (Show-KeyForm)) { return }
        }
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Multiselect = $true
        $dialog.Title = "Scan with VirusTotal"
        $dialog.Filter = "All files (*.*)|*.*"
        $owner = New-Object System.Windows.Forms.Form
        $owner.TopMost = $true
        $owner.ShowInTaskbar = $false
        $owner.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
        $owner.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
        $owner.Location = New-Object System.Drawing.Point -32000, -32000
        $owner.Size = New-Object System.Drawing.Size 1, 1
        $owner.Opacity = 0
        $owner.Show()
        $owner.Activate()
        try {
            $result = $dialog.ShowDialog($owner)
        } finally {
            $owner.Close()
            $owner.Dispose()
        }
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            foreach ($name in @($dialog.FileNames)) { Add-Queue $name }
            Show-Panel
        }
    } finally {
        Complete-Busy
    }
}

function Add-ClipboardFiles {
    try {
        if (-not [System.Windows.Forms.Clipboard]::ContainsFileDropList()) {
            $script:notify.ShowBalloonTip(4000, "VirusTotal Tray", "Copy files in Explorer, then try again.", [System.Windows.Forms.ToolTipIcon]::Info)
            return
        }
        $any = $false
        foreach ($path in @([System.Windows.Forms.Clipboard]::GetFileDropList())) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                Add-Queue $path
                $any = $true
            }
        }
        if (-not $any) {
            $script:notify.ShowBalloonTip(4000, "VirusTotal Tray", "The clipboard has no files.", [System.Windows.Forms.ToolTipIcon]::Info)
            return
        }
        Show-Panel
    } catch {
        Write-Log $_.Exception.Message
    }
}

function Copy-Scan([string]$Id) {
    $scan = Find-Scan $Id
    $text = $Id
    if ($scan) {
        $kind = [string]$scan["kind"]
        if ($kind -eq "url" -and $scan["path"]) { $text = [string]$scan["path"] }
        elseif ($kind -eq "ip" -and $scan["id"]) { $text = [string]$scan["id"] }
        elseif ($scan["sha256"]) { $text = [string]$scan["sha256"] }
    }
    if ($text) { Set-Clipboard -Value $text }
    Send-Idle
}

function Open-Report([string]$Id) {
    $scan = Find-Scan $Id
    $kind = "file"
    $target = $Id
    if ($scan) {
        if ($scan["kind"]) { $kind = [string]$scan["kind"] }
        if ($kind -eq "ip") { $target = [string]$scan["id"] }
        elseif ($scan["sha256"]) { $target = [string]$scan["sha256"] }
    }
    if ($target -notmatch '^[A-Za-z0-9:._~-]+$') { Send-Idle; return }
    $page = "https://www.virustotal.com/gui/file/$target"
    if ($kind -eq "url") { $page = "https://www.virustotal.com/gui/url/$target" }
    elseif ($kind -eq "ip") { $page = "https://www.virustotal.com/gui/ip-address/$target" }
    Start-Process $page
    Send-Idle
}

function Start-Rescan([string]$Id) {
    if ($Id -notmatch '^[A-Za-z0-9:._~-]+$') { Send-Idle; return }
    if ($script:busy) { $script:afterBusy = "rescan:$Id"; return }
    $script:busy = $true
    try { Invoke-Rescan $Id }
    finally { Complete-Busy }
}

function Get-Edge {
    foreach ($path in @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
    )) {
        if (Test-Path -LiteralPath $path) { return $path }
    }
    return $null
}

function Find-VtWindow {
    $script:vtHwnd = [IntPtr]::Zero
    $callback = [VtWindow+EnumProc]{
        param($hwnd, $lparam)
        $builder = New-Object System.Text.StringBuilder 512
        [void][VtWindow]::GetWindowText($hwnd, $builder, $builder.Capacity)
        $foundTitle = $builder.ToString()
        if ($foundTitle.StartsWith("VirusTotal Tray") -or $foundTitle.StartsWith("VirusTotal Hotbar")) {
            $script:vtHwnd = $hwnd
            return $false
        }
        return $true
    }
    [void][VtWindow]::EnumWindows($callback, [IntPtr]::Zero)
    return $script:vtHwnd
}

function Get-WindowTitle([IntPtr]$Hwnd) {
    if ($Hwnd -eq [IntPtr]::Zero) { return "" }
    $builder = New-Object System.Text.StringBuilder 4096
    [void][VtWindow]::GetWindowText($Hwnd, $builder, $builder.Capacity)
    return $builder.ToString()
}

function Get-PanelOrigin {
    $area = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $width = 400
    $height = 700
    return @{
        X = $area.Right - $width - 16
        Y = [Math]::Max($area.Top + 16, $area.Bottom - $height - 12)
        Width = $width
        Height = $height
    }
}

function Move-VtWindow([IntPtr]$Hwnd) {
    $origin = Get-PanelOrigin
    [void][VtWindow]::ShowWindow($Hwnd, 9)
    [void][VtWindow]::MoveWindow($Hwnd, $origin.X, $origin.Y, $origin.Width, $origin.Height, $true)
    [void][VtWindow]::SetForegroundWindow($Hwnd)
}

function Show-Panel {
    $hwnd = Find-VtWindow
    if ($hwnd -ne [IntPtr]::Zero) {
        Move-VtWindow $hwnd
        return
    }
    if (-not $script:edge) {
        [System.Windows.Forms.MessageBox]::Show("Microsoft Edge is required to show the panel.", "VirusTotal Tray") | Out-Null
        return
    }
    $origin = Get-PanelOrigin
    $html = (Resolve-Path (Join-Path $script:root "panel\index.html")).Path
    $uri = ([System.Uri]$html).AbsoluteUri
    $profile = Join-Path $script:dataDir "edge"
    $arguments = "--app=`"$uri`" --window-size=$($origin.Width),$($origin.Height) --window-position=$($origin.X),$($origin.Y) --user-data-dir=`"$profile`" --no-first-run --no-default-browser-check"
    Start-Process -FilePath $script:edge -ArgumentList $arguments | Out-Null
    $script:placedPanel = $false
    $script:positionUntil = (Get-Date).AddSeconds(8)
}

function Hide-Panel {
    $hwnd = Find-VtWindow
    if ($hwnd -ne [IntPtr]::Zero) { [void][VtWindow]::ShowWindow($hwnd, 0) }
}

function Close-Panel {
    $hwnd = Find-VtWindow
    if ($hwnd -ne [IntPtr]::Zero) { [void][VtWindow]::SendMessage($hwnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) }
}

function Test-PanelShown([IntPtr]$Hwnd) {
    if ($Hwnd -eq [IntPtr]::Zero) { return $false }
    # Minimized windows keep WS_VISIBLE, so IsWindowVisible alone treats them as open.
    if ([VtWindow]::IsIconic($Hwnd)) { return $false }
    return [VtWindow]::IsWindowVisible($Hwnd)
}

function Toggle-Panel {
    $hwnd = Find-VtWindow
    if (Test-PanelShown $hwnd) { Hide-Panel }
    else { Show-Panel }
}

function Handle-PanelTitle {
    $hwnd = Find-VtWindow
    if ($hwnd -eq [IntPtr]::Zero) { return }
    $title = Get-WindowTitle $hwnd
    if ($title -eq "VirusTotal Tray") {
        $script:handledTitle = ""
        return
    }
    if ($title -eq "VirusTotal Tray - close") {
        Hide-Panel
        return
    }
    if ($title -eq $script:handledTitle) { return }
    if (-not $title.StartsWith("VirusTotal Tray - ")) { return }
    $script:handledTitle = $title
    $action = $title.Substring("VirusTotal Tray - ".Length)
    if ($action -eq "pick") { Show-FileDialog }
    elseif ($action -eq "key") { Show-KeyDialog }
    elseif ($action -eq "indicator") { Focus-Indicator }
    elseif ($action.StartsWith("url:")) { Submit-QueuedUrl $action.Substring(4) }
    elseif ($action.StartsWith("copy:")) { Copy-Scan $action.Substring(5) }
    elseif ($action.StartsWith("open:")) { Open-Report $action.Substring(5) }
    elseif ($action.StartsWith("rescan:")) { Start-Rescan $action.Substring(7) }
    elseif ($action -eq "watch:1" -or $action -eq "watch:0") {
        Save-WatchSettings ($action -eq "watch:1") ([bool]$script:notifyFlagged)
        Send-Idle
    }
    elseif ($action -eq "notify:1" -or $action -eq "notify:0") {
        Save-WatchSettings ([bool]$script:watchDownloads) ($action -eq "notify:1")
        Send-Idle
    }
    else { Send-Idle }
}

# Original owl mark, not the VirusTotal trademark. Keep in sync with panel/assets/favicon.svg.
# Layers paint in order on a 24x24 grid; the eyes stay large so they still read at 16 px.
$script:markBodyPath = "M3.6 2.4C5.4 3.1 7.2 4.1 8.4 5C10.8 4.4 13.2 4.4 15.6 5C16.8 4.1 18.6 3.1 20.4 2.4C20.9 4.6 20.8 6.6 20.2 8.4C21.4 12 21 17.4 17.8 20.3C15.4 22.5 8.6 22.5 6.2 20.3C3 17.4 2.6 12 3.8 8.4C3.2 6.6 3.1 4.6 3.6 2.4Z"
$script:markPupilPath = "M8.5 8.55C9.25 8.55 9.85 9.15 9.85 9.9C9.85 10.65 9.25 11.25 8.5 11.25C7.75 11.25 7.15 10.65 7.15 9.9C7.15 9.15 7.75 8.55 8.5 8.55ZM15.5 8.55C16.25 8.55 16.85 9.15 16.85 9.9C16.85 10.65 16.25 11.25 15.5 11.25C14.75 11.25 14.15 10.65 14.15 9.9C14.15 9.15 14.75 8.55 15.5 8.55Z"
$script:markLayers = @(
    @{ Data = $script:markBodyPath; Color = @(78, 157, 151) },
    @{ Data = "M4.3 11.6C3.4 15.2 4.4 18.8 7.4 20.9C6.4 17.8 6.6 14.4 7.9 12.4C6.6 12.4 5.3 12.1 4.3 11.6ZM19.7 11.6C20.6 15.2 19.6 18.8 16.6 20.9C17.6 17.8 17.4 14.4 16.1 12.4C17.4 12.4 18.7 12.1 19.7 11.6Z"; Color = @(46, 107, 116) },
    @{ Data = "M12 12.6C15 12.6 16.8 15 16.8 17.4C16.8 19.8 14.8 21.4 12 21.4C9.2 21.4 7.2 19.8 7.2 17.4C7.2 15 9 12.6 12 12.6Z"; Color = @(246, 227, 191) },
    @{ Data = "M8.5 6.3C10.38 6.3 11.9 7.82 11.9 9.7C11.9 11.58 10.38 13.1 8.5 13.1C6.62 13.1 5.1 11.58 5.1 9.7C5.1 7.82 6.62 6.3 8.5 6.3ZM15.5 6.3C17.38 6.3 18.9 7.82 18.9 9.7C18.9 11.58 17.38 13.1 15.5 13.1C13.62 13.1 12.1 11.58 12.1 9.7C12.1 7.82 13.62 6.3 15.5 6.3Z"; Color = @(255, 248, 232) },
    @{ Data = "M8.5 7.6C9.77 7.6 10.8 8.63 10.8 9.9C10.8 11.17 9.77 12.2 8.5 12.2C7.23 12.2 6.2 11.17 6.2 9.9C6.2 8.63 7.23 7.6 8.5 7.6ZM15.5 7.6C16.77 7.6 17.8 8.63 17.8 9.9C17.8 11.17 16.77 12.2 15.5 12.2C14.23 12.2 13.2 11.17 13.2 9.9C13.2 8.63 14.23 7.6 15.5 7.6Z"; Color = @(240, 150, 50) },
    @{ Data = $script:markPupilPath; Color = @(38, 50, 92) },
    @{ Data = "M10.7 12.3H13.3L12 14.5Z"; Color = @(242, 160, 40) }
)

function New-GlyphPath([string]$Data, [double]$Scale) {
    $culture = [Globalization.CultureInfo]::InvariantCulture
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath ([System.Drawing.Drawing2D.FillMode]::Alternate)
    $tokens = @([regex]::Matches($Data, '[MLHVCSZ]|-?(?:\d+\.?\d*|\.\d+)') | ForEach-Object { $_.Value })
    $i = 0; $cmd = ""; $prev = ""
    $x = 0.0; $y = 0.0; $sx = 0.0; $sy = 0.0; $cx = 0.0; $cy = 0.0
    $pt = { param($px, $py) New-Object System.Drawing.PointF ([float]($px * $Scale)), ([float]($py * $Scale)) }
    while ($i -lt $tokens.Count) {
        $token = $tokens[$i]
        if ($token -match '^[A-Z]$') {
            $cmd = $token; $i++
            if ($cmd -eq "Z") { $path.CloseFigure(); $x = $sx; $y = $sy; $prev = "Z" }
            elseif ($cmd -eq "M") { $path.StartFigure() }
            continue
        }
        $n = @()
        $count = switch ($cmd) { "H" { 1 } "V" { 1 } "C" { 6 } "S" { 4 } default { 2 } }
        for ($k = 0; $k -lt $count; $k++) { $n += [double]::Parse($tokens[$i + $k], $culture) }
        $i += $count
        switch ($cmd) {
            "M" { $x = $n[0]; $y = $n[1]; $sx = $x; $sy = $y; $cmd = "L" }
            "L" { $path.AddLine((& $pt $x $y), (& $pt $n[0] $n[1])); $x = $n[0]; $y = $n[1] }
            "H" { $path.AddLine((& $pt $x $y), (& $pt $n[0] $y)); $x = $n[0] }
            "V" { $path.AddLine((& $pt $x $y), (& $pt $x $n[0])); $y = $n[0] }
            "C" {
                $path.AddBezier((& $pt $x $y), (& $pt $n[0] $n[1]), (& $pt $n[2] $n[3]), (& $pt $n[4] $n[5]))
                $cx = $n[2]; $cy = $n[3]; $x = $n[4]; $y = $n[5]
            }
            "S" {
                $c1x = $x; $c1y = $y
                if ($prev -eq "C" -or $prev -eq "S") { $c1x = 2 * $x - $cx; $c1y = 2 * $y - $cy }
                $path.AddBezier((& $pt $x $y), (& $pt $c1x $c1y), (& $pt $n[0] $n[1]), (& $pt $n[2] $n[3]))
                $cx = $n[0]; $cy = $n[1]; $x = $n[2]; $y = $n[3]
            }
        }
        $prev = $cmd
    }
    return $path
}

function Get-TrayIconSize {
    $dpi = 96
    try {
        $applied = Get-ItemPropertyValue -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name AppliedDPI -ErrorAction Stop
        if ($applied -ge 96) { $dpi = [int]$applied }
    } catch {}
    return [int][Math]::Round(16 * $dpi / 96)
}

function New-GlyphBitmap([int]$Size) {
    $bitmap = New-Object System.Drawing.Bitmap $Size, $Size
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.Clear([System.Drawing.Color]::Transparent)
    $scale = $Size / 24.0
    foreach ($layer in $script:markLayers) {
        $glyph = New-GlyphPath $layer.Data $scale
        $brush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, $layer.Color[0], $layer.Color[1], $layer.Color[2]))
        $graphics.FillPath($brush, $glyph)
        $brush.Dispose(); $glyph.Dispose()
    }
    $graphics.Dispose()
    return $bitmap
}

function New-HIcon([System.Drawing.Bitmap]$Bitmap) {
    $handle = $Bitmap.GetHicon()
    $Bitmap.Dispose()
    return $handle
}

function Write-AppIcon([string]$Path) {
    $sizes = @(16, 20, 24, 32, 40, 48, 64, 256)
    $images = foreach ($size in $sizes) {
        $bitmap = New-GlyphBitmap $size
        $stream = New-Object System.IO.MemoryStream
        $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
        $bitmap.Dispose()
        ,$stream.ToArray()
    }
    $file = New-Object System.IO.MemoryStream
    $writer = New-Object System.IO.BinaryWriter $file
    $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$sizes.Count)
    $offset = 6 + 16 * $sizes.Count
    for ($k = 0; $k -lt $sizes.Count; $k++) {
        $dim = if ($sizes[$k] -ge 256) { 0 } else { $sizes[$k] }
        $writer.Write([byte]$dim); $writer.Write([byte]$dim); $writer.Write([byte]0); $writer.Write([byte]0)
        $writer.Write([uint16]1); $writer.Write([uint16]32)
        $writer.Write([uint32]$images[$k].Length); $writer.Write([uint32]$offset)
        $offset += $images[$k].Length
    }
    foreach ($image in $images) { $writer.Write($image) }
    $writer.Flush()
    [System.IO.File]::WriteAllBytes($Path, $file.ToArray())
    $writer.Dispose()
}

function Update-Tooltip {
    if (-not $script:notify) { return }
    $text = "VirusTotal Tray"
    if ($script:activity) { $text = [string]$script:activity }
    elseif ($script:scans -and $script:scans.Count -gt 0 -and $script:scans[0]["status"] -eq "completed") {
        $latest = $script:scans[0]
        $malicious = 0
        if ($latest["stats"]) { $malicious = [int]$latest["stats"]["malicious"] }
        if ($malicious -gt 0) { $text = "$malicious flagged - $($latest["name"])" }
        else { $text = "Clean - $($latest["name"])" }
    }
    if ($text.Length -gt 120) { $text = $text.Substring(0, 120) }
    try { $script:notify.Text = $text } catch { $script:notify.Text = "VirusTotal Tray" }
}

function Update-TrayIcon {
    if (-not $script:notify) { return }
    $key = "$(Get-TrayIconSize)"
    if ($key -eq $script:iconKey) { return }
    $script:iconKey = $key
    $handle = New-HIcon (New-GlyphBitmap (Get-TrayIconSize))
    $script:notify.Icon = [System.Drawing.Icon]::FromHandle($handle)
    if ($script:iconHandle -ne [IntPtr]::Zero) { [void][VtWindow]::DestroyIcon($script:iconHandle) }
    $script:iconHandle = $handle
}

function Set-PanelIcon([IntPtr]$Hwnd) {
    $WM_SETICON = 0x0080
    $WM_GETICON = 0x007F
    if ($Hwnd -ne $script:brandedHwnd) {
        $relaunch = "`"" + (Get-LauncherPath) + "`""
        $ok = [VtShell]::SetAppIdentity($Hwnd, "VirusTotalTray.Panel", $relaunch, "$($script:appIconPath),0", "VirusTotal Tray")
        if (-not $ok) { Write-Log "taskbar identity was not applied" }
        $script:brandedHwnd = $Hwnd
    }
    $current = [VtWindow]::SendMessage($Hwnd, $WM_GETICON, [IntPtr]1, [IntPtr]::Zero)
    if ($current -ne $script:panelBigIcon) {
        [void][VtWindow]::SendMessage($Hwnd, $WM_SETICON, [IntPtr]0, $script:panelSmallIcon)
        [void][VtWindow]::SendMessage($Hwnd, $WM_SETICON, [IntPtr]1, $script:panelBigIcon)
    }
}

function Invoke-SelfTest {
    $failed = New-Object System.Collections.Generic.List[string]
    function Assert-True([bool]$Condition, [string]$Name) {
        if (-not $Condition) { $failed.Add($Name) }
    }
    Assert-True (Test-VtUploadUrl "https://www.virustotal.com/api/v3/files") "https upload host"
    Assert-True (Test-VtUploadUrl "http://www.virustotal.com/_ah/upload/abc/") "http upload host"
    Assert-True (-not (Test-VtUploadUrl "https://evil.example/upload")) "reject other host"
    Assert-True (-not (Test-VtUploadUrl "https://user:pass@www.virustotal.com/upload")) "reject user info"
    $sample = Join-Path $script:root "hash-sample.bin"
    [System.IO.File]::WriteAllBytes($sample, [Text.Encoding]::ASCII.GetBytes("abc"))
    $hash = Get-FileSha256 $sample
    Assert-True ($hash -eq "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") "sha256"
    $body = New-GlyphPath $script:markBodyPath 1
    $pupils = New-GlyphPath $script:markPupilPath 1
    Assert-True ($body.IsVisible(12, 16) -and $body.IsVisible(4, 3.5) -and $body.IsVisible(20, 3.5)) "owl body and tufts"
    Assert-True (-not $body.IsVisible(12, 3.5)) "owl gap between tufts"
    Assert-True ($pupils.IsVisible(8.5, 9.9) -and $pupils.IsVisible(15.5, 9.9) -and -not $pupils.IsVisible(12, 9.9)) "owl pupils"
    $body.Dispose(); $pupils.Dispose()
    $stats = Get-Stats ([pscustomobject]@{ malicious = 2; suspicious = 1; undetected = 3; harmless = 4; timeout = 0; failure = 0 })
    Assert-True ([int]$stats["malicious"] -eq 2) "stats"
    $hits = Get-Hits ([pscustomobject]@{
        A = [pscustomobject]@{ category = "malicious"; engine_name = "One"; result = "Trojan" }
        B = [pscustomobject]@{ category = "undetected"; engine_name = "Two"; result = $null }
        C = [pscustomobject]@{ category = "suspicious"; engine_name = "Three"; result = "Maybe" }
    })
    Assert-True ($hits.Count -eq 2 -and $hits[0]["engine"] -eq "One") "hits"
    $backup = $script:scans
    $script:scans = New-Object System.Collections.Generic.List[object]
    $script:scans.Add(@{
        sha256 = "abc"
        name = "a.bin"
        status = "uploading"
        stats = @{ malicious = 1; suspicious = 0; undetected = 0; harmless = 0; timeout = 0; failure = 0 }
        hits = (New-Object System.Collections.Generic.List[object])
    })
    Save-History
    Load-History
    Assert-True ($script:scans.Count -eq 1 -and $script:scans[0]["status"] -eq "error") "interrupted upload"
    Assert-True ([int]$script:scans[0]["stats"]["malicious"] -eq 1) "history stats"
    $script:scans = $backup
    Save-ApiKey "test-key"
    Assert-True ((Get-ApiKey) -eq "test-key") "api key"
    $legacyBlob = [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect(
        [Text.Encoding]::UTF8.GetBytes("legacy-key"),
        [Text.Encoding]::UTF8.GetBytes("VirusTotal-Hotbar"),
        [Security.Cryptography.DataProtectionScope]::CurrentUser
    ))
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText((Get-SettingsPath), (ConvertTo-Json -InputObject @{ apiKeyProtected = $legacyBlob } -Compress), $utf8)
    Assert-True ((Get-ApiKey) -eq "legacy-key") "legacy key"
    $stored = [System.IO.File]::ReadAllText((Get-SettingsPath))
    Assert-True ($stored -notlike "*test-key*") "key not plaintext"
    Assert-True ($stored -like "*apiKeyProtected*") "protected field"
    Assert-True ((Get-SettingsPath) -eq (Join-Path $script:settingsDir "settings.json")) "settings path"
    Assert-True ((Get-HistoryPath) -eq (Join-Path $script:dataDir "history.json")) "history path"
    $asUrl = ConvertTo-Indicator "https://example.com/a"
    Assert-True ($asUrl["kind"] -eq "url" -and $asUrl["value"] -eq "https://example.com/a") "url"
    $asHost = ConvertTo-Indicator "example.com/path"
    Assert-True ($asHost["kind"] -eq "url" -and $asHost["value"] -eq "https://example.com/path") "host url"
    $asIp = ConvertTo-Indicator "8.8.8.8"
    Assert-True ($asIp["kind"] -eq "ip" -and $asIp["value"] -eq "8.8.8.8") "ipv4"
    $asWebIp = ConvertTo-Indicator "http://8.8.8.8/index"
    Assert-True ($asWebIp["kind"] -eq "url") "ip inside url"
    Assert-True ($null -eq (ConvertTo-Indicator "not an address")) "reject text"
    Assert-True ((Get-StringSha256 "abc") -eq "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") "string sha"
    Save-WatchSettings $true $false
    $flags = Read-Settings
    Assert-True ($flags.watchDownloads -eq $true -and $flags.notifyFlagged -eq $false) "watch flag"
    Assert-True ((Get-ApiKey) -eq "legacy-key") "key kept with watch"
    Save-ApiKey "test-key"
    Assert-True ((Read-Settings).watchDownloads -eq $true) "watch kept with key"
    Assert-True (Test-DownloadCandidate "report.exe") "download exe"
    Assert-True (-not (Test-DownloadCandidate "report.exe.crdownload")) "skip crdownload"
    Assert-True (-not (Test-DownloadCandidate "desktop.ini")) "skip desktop.ini"
    Assert-True (-not (Test-DownloadCandidate "file.part")) "skip part"
    $probe = New-Object VtDownloadWatch
    $probe.Paths.Enqueue("C:\not-a-download.exe")
    $got = ""
    Assert-True ($probe.Paths.TryDequeue([ref]$got) -and $got -eq "C:\not-a-download.exe") "download queue"
    $probe.Dispose()
    Assert-True ($null -eq $script:downloadWatch) "selftest does not watch"
    if ($failed.Count -gt 0) { throw ("FAILED " + ($failed -join ", ")) }
    Write-Output "SELFTEST OK"
}

if ($SelfTest) {
    $previousRoot = $script:root
    $previousSettings = $script:settingsDir
    $previousData = $script:dataDir
    $scratch = Join-Path $previousRoot ".selftest"
    $script:root = $scratch
    $script:settingsDir = Join-Path $scratch "settings"
    $script:dataDir = Join-Path $scratch "data"
    New-Item -ItemType Directory -Force -Path $script:root | Out-Null
    $script:activity = ""
    $script:notice = ""
    $script:scans = New-Object System.Collections.Generic.List[object]
    try {
        Invoke-SelfTest
    } catch {
        Write-Output $_.ScriptStackTrace
        Write-Output $_.Exception.ToString()
        throw
    } finally {
        $script:root = $previousRoot
        $script:settingsDir = $previousSettings
        $script:dataDir = $previousData
        if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
    }
    exit 0
}

$script:queue = New-Object System.Collections.Generic.List[string]
$script:scans = New-Object System.Collections.Generic.List[object]
$script:activity = ""
$script:notice = ""
$script:busy = $false
$script:afterBusy = ""
$script:commandSeq = 0
$script:handledTitle = ""
$script:lastPoll = [datetime]::MinValue
$script:pollIndex = -1
$script:edge = Get-Edge
$script:placedPanel = $false
$script:positionUntil = [datetime]::MinValue
$script:iconKey = ""
$script:iconHandle = [IntPtr]::Zero
$script:brandedHwnd = [IntPtr]::Zero
$script:notify = $null
$script:watchDownloads = $false
$script:notifyFlagged = $false
$script:downloadWatch = $null
$script:downloadPending = @{}
$script:downloadSeen = @{}
$script:watchedPaths = @{}
$script:downloadCheck = [datetime]::MinValue

$mutex = New-Object System.Threading.Mutex($false, "Local\VirusTotalTray")
$owned = $false
try {
    $owned = $mutex.WaitOne(0)
} catch [System.Threading.AbandonedMutexException] {
    $owned = $true
}
if (-not $owned) {
    if ($Dropped) { Write-Inbox @($Dropped) }
    exit 0
}

function Get-LauncherPath {
    return Join-Path $script:root "VirusTotal Tray.exe"
}

function Save-StartupShortcut([string]$Path) {
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($Path)
    $link.TargetPath = Get-LauncherPath
    $link.WorkingDirectory = $script:root
    $link.WindowStyle = 7
    $link.Description = "VirusTotal Tray"
    if ($script:appIconPath -and (Test-Path -LiteralPath $script:appIconPath)) {
        $link.IconLocation = "$($script:appIconPath),0"
    }
    $link.Save()
}

function Test-ShortcutTargetsVbs([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($Path)
    return ([string]$link.TargetPath) -like "*.vbs"
}

function Import-LegacyStore {
    function Move-LegacyFolder([string]$OldPath, [string]$NewPath) {
        if (-not (Test-Path -LiteralPath $OldPath)) { return }
        if (Test-Path -LiteralPath $NewPath) { return }
        try { Move-Item -LiteralPath $OldPath -Destination $NewPath -ErrorAction Stop } catch {}
    }
    Move-LegacyFolder (Join-Path $env:APPDATA "VirusTotal-Hotbar") $script:settingsDir
    Move-LegacyFolder (Join-Path $env:LOCALAPPDATA "VirusTotal-Hotbar") $script:dataDir
    $startup = [Environment]::GetFolderPath("Startup")
    $oldLink = Join-Path $startup "VirusTotal Hotbar.lnk"
    $newLink = Join-Path $startup "VirusTotal Tray.lnk"
    if ((Test-Path -LiteralPath $oldLink) -and -not (Test-Path -LiteralPath $newLink)) {
        Save-StartupShortcut $newLink
    }
    if (Test-Path -LiteralPath $oldLink) { Remove-Item -LiteralPath $oldLink -Force }
    if (Test-ShortcutTargetsVbs $newLink) { Save-StartupShortcut $newLink }
}

[System.Windows.Forms.Application]::EnableVisualStyles()
Import-LegacyStore
Close-Panel
try {
    Load-History
    Import-WatchSettings
    Publish-Data
    if ($Dropped) {
        foreach ($path in @($Dropped)) { Add-Queue $path }
    }

    Ensure-Directory $script:dataDir
    # Windows caches icons by file path, so the name changes whenever the mark does.
    $markId = (Get-StringSha256 (($script:markLayers | ForEach-Object { "$($_.Color -join ',')|$($_.Data)" }) -join "`n")).Substring(0, 8)
    $script:appIconPath = Join-Path $script:dataDir "VirusTotalTray-$markId.ico"
    try { Write-AppIcon $script:appIconPath } catch { Write-Log ("icon: " + $_.Exception.Message) }
    Get-ChildItem -LiteralPath $script:dataDir -Filter "VirusTotal*.ico" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -ne $script:appIconPath } |
        ForEach-Object { try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch {} }
    $startupLink = Join-Path ([Environment]::GetFolderPath("Startup")) "VirusTotal Tray.lnk"
    if (Test-Path -LiteralPath $startupLink) { Save-StartupShortcut $startupLink }
    $dpiScale = (Get-TrayIconSize) / 16.0
    $script:panelSmallIcon = New-HIcon (New-GlyphBitmap (Get-TrayIconSize))
    $script:panelBigIcon = New-HIcon (New-GlyphBitmap ([int][Math]::Round(32 * $dpiScale)))

    $notify = New-Object System.Windows.Forms.NotifyIcon
    $script:notify = $notify
    Update-TrayIcon
    $notify.Text = "VirusTotal Tray"
    $notify.Visible = $true
    Update-Tooltip

    $menu = New-Object System.Windows.Forms.ContextMenuStrip
    $openItem = $menu.Items.Add("Open")
    $scanItem = $menu.Items.Add("Scan file")
    $indicatorItem = $menu.Items.Add("Scan URL or IP")
    $pasteItem = $menu.Items.Add("Scan copied files")
    [void]$menu.Items.Add("-")
    $keyItem = $menu.Items.Add("API key")
    $folderItem = $menu.Items.Add("App folder")
    $startupItem = $menu.Items.Add("Start with Windows")
    [void]$menu.Items.Add("-")
    $quitItem = $menu.Items.Add("Quit")
    $notify.ContextMenuStrip = $menu

    $openItem.add_Click({ Show-Panel })
    $scanItem.add_Click({ Show-FileDialog })
    $indicatorItem.add_Click({ Focus-Indicator })
    $pasteItem.add_Click({ Add-ClipboardFiles })
    $keyItem.add_Click({ Show-KeyDialog })
    $folderItem.add_Click({ Start-Process explorer.exe $script:root })
    $startupItem.add_Click({
        $startup = [Environment]::GetFolderPath("Startup")
        $linkPath = Join-Path $startup "VirusTotal Tray.lnk"
        if (Test-Path -LiteralPath $linkPath) {
            Remove-Item -LiteralPath $linkPath -Force
            return
        }
        Save-StartupShortcut $linkPath
    })
    $menu.add_Opening({
        $startupItem.Checked = Test-Path -LiteralPath (Join-Path ([Environment]::GetFolderPath("Startup")) "VirusTotal Tray.lnk")
    })
    $quitItem.add_Click({
        Hide-Panel
        $notify.Visible = $false
        $notify.Dispose()
        if ($script:iconHandle -ne [IntPtr]::Zero) { [void][VtWindow]::DestroyIcon($script:iconHandle) }
        if ($script:panelSmallIcon -ne [IntPtr]::Zero) { [void][VtWindow]::DestroyIcon($script:panelSmallIcon) }
        if ($script:panelBigIcon -ne [IntPtr]::Zero) { [void][VtWindow]::DestroyIcon($script:panelBigIcon) }
        try { [void]$mutex.ReleaseMutex() } catch {}
        [System.Windows.Forms.Application]::Exit()
    })

    $notify.add_MouseUp({
        param($sender, $eventArgs)
        if ($eventArgs.Button -eq [System.Windows.Forms.MouseButtons]::Left) { Toggle-Panel }
        elseif ($eventArgs.Button -eq [System.Windows.Forms.MouseButtons]::Middle) { Send-Command "next" }
    })

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 400
    $timer.add_Tick({
        try { Settle-Downloads } catch { Write-Log $_.Exception.Message }
        if ($script:busy) { return }
        try {
            Update-TrayIcon
            Read-Inbox
            Handle-PanelTitle
            if (-not $script:busy) { Poll-Analyses }
            if (-not $script:busy) { Process-Next }
            $hwnd = Find-VtWindow
            if ($hwnd -eq [IntPtr]::Zero) { return }
            Set-PanelIcon $hwnd
            if (-not $script:placedPanel -and (Get-Date) -lt $script:positionUntil) {
                Move-VtWindow $hwnd
                $script:placedPanel = $true
            }
        } catch {
            Write-Log $_.Exception.Message
        }
    })
    $timer.Start()

    if ($script:queue.Count -gt 0) { Show-Panel }
    [System.Windows.Forms.Application]::Run()
} catch {
    Write-Log $_.Exception.ToString()
    exit 1
}
