@echo off
setlocal
set "GANET_ROOT=%~dp0"
set "GANET_PYTHON_SHIM=%USERPROFILE%\.genericagent\ganet\ga_python.cmd"

set "GANET_PYTHON="
if exist "%GANET_PYTHON_SHIM%" call "%GANET_PYTHON_SHIM%"

if not defined GANET_PYTHON (
  >&2 echo GAnet host binding is missing.
  >&2 echo Ask GenericAgent to configure device interconnect first.
  exit /b 1
)
if not exist "%GANET_PYTHON%" (
  >&2 echo The bound GenericAgent Python no longer exists.
  >&2 echo Ask GenericAgent to repair device interconnect.
  exit /b 1
)

set "PYTHONPATH=%GANET_ROOT%"
"%GANET_PYTHON%" -m ganet %*
exit /b %errorlevel%
