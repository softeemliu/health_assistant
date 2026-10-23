@echo off
rem health_assistant (health_assistant) - GUI launcher for scheduled tasks / command line.
rem For normal use just double-click the .pyw file in the project root -- a .bat
rem always flashes one cmd window first, and that cannot be hidden from inside.
rem Keep this file ASCII-only: cmd.exe reads .cmd/.bat in the OEM codepage (936
rem here), so UTF-8 Chinese comments can corrupt the following lines.
chcp 65001 >nul
cd /d "%~dp0.."

set "PYW=C:\Python3\pythonw.exe"
if not exist "%PYW%" set "PYW=C:\Python3\python.exe"
if not exist "%PYW%" set "PYW=pythonw.exe"

start "" "%PYW%" "%~dp0..\health_assistant_app.py"
exit /b
