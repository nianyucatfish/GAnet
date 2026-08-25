@echo off
setlocal
set "GANET_ROOT=%~dp0"
set "GANET_PYTHON=%GANET_ROOT%runtime\python\python.exe"

if not exist "%GANET_PYTHON%" (
  >&2 echo GAnet component runtime is missing.
  >&2 echo Re-download the complete GAnet component.
  exit /b 1
)

set "PYTHONPATH=%GANET_ROOT%runtime\site-packages"
"%GANET_PYTHON%" -m ganet %*
exit /b %errorlevel%
