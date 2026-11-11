@echo off
rem A newer build may be waiting in bin_new: move it in when Sour is not running.
if not exist "%~dp0bin_new\Sour.exe" goto run
tasklist /fi "imagename eq Sour.exe" | find /i "Sour.exe" >nul
if not errorlevel 1 goto run
robocopy "%~dp0bin_new" "%~dp0bin" /E /MOVE /NFL /NDL /NJH /NJS >nul
:run
start "" "%~dp0bin\Sour.exe" %*
