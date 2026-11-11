@echo off
rem Builds Sour (Release). If Sour is running, bin\ is locked, so the build goes to bin_new\
rem and Sour.cmd moves it into bin\ the next time Sour is started.
setlocal
set OUT=%~dp0bin
tasklist /fi "imagename eq Sour.exe" | find /i "Sour.exe" >nul
if not errorlevel 1 set OUT=%~dp0bin_new
echo Building to %OUT%
dotnet build "%~dp0src\Sour\Sour.csproj" -c Release -o "%OUT%" --nologo -v minimal
if errorlevel 1 exit /b 1
echo.
echo Done. Run Sour.cmd to start it, or test.cmd to run the automated checks.
