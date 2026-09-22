@echo off
title Wazuh lab
REM The front door. Opens the lab dashboard, which is where the lab is started, watched
REM and stopped from. It asks for elevation once, because Hyper-V will not report VM state
REM to an ordinary session. It starts nothing by itself.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0dashboard\Start-LabDashboard.ps1" %*
