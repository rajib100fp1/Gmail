@echo off
setlocal
set "SHORTCUT=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Gmail OTP Local Server.lnk"
if exist "%SHORTCUT%" del /f /q "%SHORTCUT%"
echo Auto-start removed. The server will no longer start automatically with Windows.
pause
endlocal
