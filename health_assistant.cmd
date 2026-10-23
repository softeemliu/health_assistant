@echo off
rem ===========================================================================
rem  health_assistant command-line entry. Works from ANY current directory:
rem
rem    "E:\Ollama\health_assistant\health_assistant.cmd" clean --kind profile
rem    "E:\Ollama\health_assistant\health_assistant.cmd" --mask -o report.md
rem
rem  Why this file exists: the package is not installed into site-packages,
rem  so "python -m health_assistant" only works when cwd is the project root.
rem  This wrapper pushd's to its own folder first, so the command is
rem  copy-paste safe anywhere. Arguments and exit code pass through.
rem
rem  NOTE: keep this file pure ASCII -- cmd.exe parses .cmd in the OEM
rem  codepage (936 here), so UTF-8 Chinese comments would corrupt the lines.
rem ===========================================================================
setlocal
pushd "%~dp0" >nul

rem Prefer C:\Python3 (it has psutil/PySide6), then py -3, then python.
set "PYEXE=C:\Python3\python.exe"
if exist "%PYEXE%" goto :run
set "PYEXE=python"
where py >nul 2>&1
if not errorlevel 1 set "PYEXE=py -3"

:run
%PYEXE% -m health_assistant %*
set "RC=%ERRORLEVEL%"
popd >nul
endlocal & exit /b %RC%
