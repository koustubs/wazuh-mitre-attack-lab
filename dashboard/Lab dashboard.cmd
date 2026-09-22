@echo off
title Wazuh lab dashboard
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-LabDashboard.ps1" %*
