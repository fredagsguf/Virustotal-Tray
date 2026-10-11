# VirusTotal Tray

A portable Windows tray app for [VirusTotal](https://www.virustotal.com). It sits in the notification area, usually under the hidden-icons arrow. You scan a file, a URL, or an IP address from the tray. The app talks to the VirusTotal API and shows the detection ratio in a small panel.

The panel is a dark popup in VirusTotal blue on navy. A teal owl is the tray icon. The owl is this app's mark, not the VirusTotal logo.

## Disclaimer

This project is not affiliated with, endorsed by, or sponsored by VirusTotal. VirusTotal is a separate service. This app only calls the public VirusTotal API.

The app does not include an API key. You create a free VirusTotal account, copy the API key from that account, and paste it into the app yourself. Lookups and uploads then run with your key, on your account.

## What you need

The app adds no runtime of its own. These already come with a current Windows install:

| Requirement | Why |
|---|---|
| Windows | Tray icon, file dialogs, and startup shortcut are Windows-only |
| Windows PowerShell 5.1 | The app is `Start-VirusTotal-Tray.ps1`. The launchers call `WindowsPowerShell\v1.0\powershell.exe` |
| Microsoft Edge | The panel is an Edge app window. The window uses its own profile under Local AppData, separate from your normal Edge profile |
| .NET Framework | Ships with Windows. Used for the tray, HTTPS, SHA-256, and encrypting the API key |
| A VirusTotal API key | Every lookup and upload sends the key. Get one at [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |
| Internet access to `www.virustotal.com` | HTTPS with TLS 1.2 |

A restricted PowerShell execution policy does not block the app. Both launchers start that one process with `-ExecutionPolicy Bypass`.

PowerShell 7 is not used. Node, Python, and an installer are not required.

## Run

Double-click **VirusTotal Tray.exe** for a silent start, or **VirusTotal Tray.cmd** from a command prompt. If the `.exe` is not in the folder, use the `.cmd`, or build the `.exe` as described below.

- Left-click the owl to open or hide the panel.
- Right-click for the menu.
- Middle-click to move to the next scan in the list.
- Drop files onto **VirusTotal Tray.exe** to queue them. Paths passed to the `.exe` or the `.cmd` are queued the same way.

Only one instance runs. A second start, including a file drop, hands the paths to the instance that is already running and then exits.

The panel opens at the bottom-right of the primary screen. Close it with Escape, or with the left-click toggle. Escape inside the URL field only leaves that field. Escape while Settings is open closes Settings first.

## API key

Choose **API key** in the tray menu, or the key button in the panel. The first scan also asks for a key if none is saved.

Windows encrypts the key for the current user account (DPAPI) and stores it in `%APPDATA%\VirusTotal-Tray\settings.json` as `apiKeyProtected`. Another Windows user, or a copy of that file on another PC, cannot open it. A leftover plain-text `apiKey` field is encrypted on the next start and is not written back.

`settings.example.json` shows the file shape. The live file is created in AppData when you save a key. It is not kept next to the app.

## Scan a file

From the panel **File** button, the **S** key, the tray menu **Scan file**, or a drop onto the `.exe`. The file dialog allows several files. **Scan copied files** uses files you copied in File Explorer.

The app works through the queue one file at a time:

1. Rejects a file over **650 MB**. VirusTotal does not accept it.
2. Asks before uploading a file over **200 MB**. Those often scan poorly.
3. Hashes the file on this PC (SHA-256) and looks up that hash.
4. If VirusTotal already has the hash, the panel loads that report.
5. If not, the app uploads the file. Files over **32 MB** request VirusTotal's large-file upload URL first. The app only posts to `virustotal.com` or a `*.virustotal.com` host.
6. The panel polls the analysis about every 20 seconds until the engines finish.

An upload can take a while. The HTTP call waits up to 20 minutes. The tray tooltip shows the current step: hashing, checking, uploading, or scanning.

A hash lookup of a report already on VirusTotal uses your API quota. A brand-new upload does not spend that lookup quota. The free API allows a small number of lookups per minute. A rate-limit response asks you to wait a minute and scan again.

Files you upload are added to the VirusTotal community dataset. Do not scan secrets or private documents.

## Scan a URL or an IP address

Paste either one into the panel field and submit it, or choose **Scan URL or IP** in the tray menu (**U** focuses the field).

Accepted input:

- An `http://` or `https://` URL, up to 2048 characters.
- A host name that contains a dot, such as `example.com/path`. The app sends it as `https://` plus that text.
- An IPv4 address (each octet 0–255) or an IPv6 address.

The app looks up the URL or address first. A known report is shown immediately. If VirusTotal has no report, a URL is submitted to the URL scan endpoint and an IP address is sent for a fresh analysis. The panel then polls the same way it does for a file.

URLs and IP addresses you submit are added to the VirusTotal community dataset.

## What the panel shows

The selected scan shows a verdict, a detection ratio, a meter, and up to 12 engine hits. Malicious hits are listed before suspicious ones. Each hit shows the engine name and the detection name.

| Verdict | Meaning |
|---|---|
| Clean | No malicious or suspicious hits |
| Suspicious | One or more engines called it suspicious, and none called it malicious |
| Malicious | One or more engines called it malicious. The headline counts those engines |
| Scanning | Hashing, checking, uploading, or waiting for engines |
| Error | The scan failed. The message is the VirusTotal error, a rejected API key, or a local limit |

The ratio is the malicious count, or the suspicious count when nothing is malicious, over the total engines that returned a result. The line under the name can include the threat label, whether the item was already on VirusTotal, uploaded, submitted, or rescanned, the file type, the size, and how long ago the scan was.

**Open report** opens the matching page on virustotal.com (file, URL, or IP). **Rescan** asks VirusTotal to analyse the same item again. If VirusTotal has not started that rescan, the panel keeps the previous report and says so. **Copy hash**, **Copy URL**, or **Copy IP** puts that value on the clipboard. **Details** shows the SHA-256 and the local path or full URL.

**Recent** keeps the last 40 scans. With two or more, you can filter **All**, **Flagged**, or **Clean**. Arrow keys or **H** / **L** move between visible scans. **J** / **K** scroll the panel. The newest scan becomes the selected one.

A manual scan that finishes as malicious raises a balloon notification. A suspicious-only manual scan does not.

## Settings

The gear in the panel header stores two switches in the same settings file:

- **Watch Downloads** watches the Downloads folder (the shell Downloads folder, or `%USERPROFILE%\Downloads` if that cannot be resolved). New files in that folder, not in subfolders, are queued. The app skips `desktop.ini`, `Thumbs.db`, and partial names ending in `.crdownload`, `.tmp`, `.part`, `.partial`, `.download`, `.opdownload`, or `.fdmdownload`. It waits until the file size is stable and greater than zero, so a browser can finish writing. This is off until you turn it on. Watched files are uploaded under the same community-dataset terms as any other file.
- **Notify when flagged** applies to watched downloads. When it is on, a balloon appears if that download is malicious or suspicious. The switch stays off while Watch Downloads is off.

## Tray menu

| Item | Action |
|---|---|
| Open | Shows the panel |
| Scan file | Multi-select file dialog |
| Scan URL or IP | Shows the panel and focuses the URL field |
| Scan copied files | Queues files copied in File Explorer |
| API key | Save or replace the key |
| App folder | Opens this folder in Explorer |
| Start with Windows | Creates or removes `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\VirusTotal Tray.lnk` |
| Quit | Hides the panel, removes the tray icon, and exits |

**Start with Windows** points the shortcut at `VirusTotal Tray.exe` in this folder, so the `.exe` has to be there. The shortcut uses the owl icon and starts minimized.

## Files the app writes

| Path | Contents |
|---|---|
| `%APPDATA%\VirusTotal-Tray\settings.json` | Encrypted API key, Watch Downloads, Notify when flagged |
| `%LOCALAPPDATA%\VirusTotal-Tray\history.json` | The last 40 scans |
| `%LOCALAPPDATA%\VirusTotal-Tray\tray.log` | Errors and other log lines |
| `%LOCALAPPDATA%\VirusTotal-Tray\inbox\` | File lists handed from a second launch to the running instance |
| `%LOCALAPPDATA%\VirusTotal-Tray\edge\` | Edge profile used only by the panel |
| `%LOCALAPPDATA%\VirusTotal-Tray\VirusTotalTray-*.ico` | Generated tray and window icon |

A scan that was hashing, checking, or uploading when the app quit is stored as an error: "Interrupted. Scan the file again."

## Files in this folder

| File | Role |
|---|---|
| `VirusTotal Tray.exe` | Silent launcher and the drop target. Build it from `Launcher.cs` if it is missing |
| `VirusTotal Tray.cmd` | Starts the same script from a command prompt |
| `Start-VirusTotal-Tray.ps1` | The tray app |
| `Launcher.cs` | Source for the silent `.exe`. It starts PowerShell with no window |
| `panel\` | The panel page (`index.html`, `app.js`, `styles.css`, `assets\favicon.svg`). It only draws data the script writes. It does not call VirusTotal itself |
| `settings.example.json` | Example of the settings file shape |
| `panel\data.js`, `panel\command.js` | Written while the app is running. Not part of the source |

## Build the silent launcher

The `.cmd` is enough to run the app. The `.exe` is what file drops and **Start with Windows** use. From this folder, in a command prompt:

```bat
%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /optimize+ /out:"VirusTotal Tray.exe" Launcher.cs
```

That compiler ships with .NET Framework on 64-bit Windows. No separate SDK is required.

## Check the script

From this folder:

```bat
powershell.exe -STA -NoProfile -ExecutionPolicy Bypass -File "Start-VirusTotal-Tray.ps1" -SelfTest
```

A good run prints `SELFTEST OK`. The check uses a temporary folder beside the script and deletes it afterward. It does not start the tray icon or watch Downloads.
