@echo off
setlocal
cd /d "%~dp0"
if not exist venv\Scripts\pythonw.exe (
  echo [1/2] Creating Python environment and installing packages...
  if not exist venv python -m venv venv
  call venv\Scripts\activate
  python -m pip install -r requirements.txt
  if errorlevel 1 (
    echo Package installation failed.
    pause
    exit /b 1
  )
)

set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
if not exist "%STARTUP%" mkdir "%STARTUP%"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ws=New-Object -ComObject WScript.Shell; $s=$ws.CreateShortcut((Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\Gmail OTP Local Server.lnk')); $s.TargetPath='wscript.exe'; $s.Arguments='"' + (Join-Path '%~dp0' 'start-background.vbs') + '"'; $s.WorkingDirectory='%~dp0'; $s.IconLocation='%SystemRoot%\System32\wscript.exe,0'; $s.Save()"
if errorlevel 1 (
  echo Could not create Startup shortcut.
  pause
  exit /b 1
)

echo.
echo ==============================================
echo Auto-start installed successfully.
echo The local server will start automatically after Windows login.
echo It runs in the background without a CMD window.
echo ==============================================
echo.
echo Starting server now...
wscript.exe "%~dp0start-background.vbs"
timeout /t 3 >nul
start "" http://127.0.0.1:5000/health
endlocal
