@echo off
powershell.exe -STA -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "%~dp0Start-VirusTotal-Tray.ps1" %*
