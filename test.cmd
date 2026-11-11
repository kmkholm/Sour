@echo off
rem Runs the automated checks of the newest build and prints the report.
setlocal
set EXE=%~dp0bin\Sour.exe
if exist "%~dp0bin_new\Sour.exe" set EXE=%~dp0bin_new\Sour.exe
"%EXE%" --selftest --out "%TEMP%\sour_selftest.txt"
type "%TEMP%\sour_selftest.txt"
