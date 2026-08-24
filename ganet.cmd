@echo off
setlocal
set "GANET_ROOT=%~dp0"

if exist "%GANET_ROOT%runtime\python.exe" (
  "%GANET_ROOT%runtime\python.exe" -m ganet %*
  exit /b %errorlevel%
)

if exist "%GANET_ROOT%.venv\Scripts\python.exe" (
  "%GANET_ROOT%.venv\Scripts\python.exe" -m ganet %*
  exit /b %errorlevel%
)

where py >nul 2>nul
if not errorlevel 1 (
  py -3 -m ganet %*
  exit /b %errorlevel%
)

where python >nul 2>nul
if not errorlevel 1 (
  python -m ganet %*
  exit /b %errorlevel%
)

>&2 echo GAnet could not find its bundled Python runtime.
>&2 echo Re-download the complete GAnet package or run setup first.
exit /b 1
