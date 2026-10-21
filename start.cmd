@echo off
setlocal
set "NEXUS_EDGE_BUN=bun.exe"
where bun.exe >nul 2>nul
if errorlevel 1 (
  if exist "%USERPROFILE%\.bun\bin\bun.exe" (
    set "NEXUS_EDGE_BUN=%USERPROFILE%\.bun\bin\bun.exe"
  ) else (
    echo Bun 1.4.3 or newer is required.
    echo Install Bun from https://bun.sh/docs/installation and open a new terminal.
    pause
    exit /b 1
  )
)
"%NEXUS_EDGE_BUN%" "%~dp0nexus-edge.ts"
set "NEXUS_EDGE_EXIT=%ERRORLEVEL%"
if not "%NEXUS_EDGE_EXIT%"=="0" pause
exit /b %NEXUS_EDGE_EXIT%
