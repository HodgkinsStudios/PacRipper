@echo off
rem PacRipper standalone Windows package staging
rem Created by Jacob Hodgkins
setlocal EnableExtensions
cd /d "%~dp0"

set "DEST=%~1"
if not defined DEST set "DEST=dist\PacRipper-Windows"

if not exist bin\PacRipper.exe (
  echo ERROR: bin\PacRipper.exe is missing. Run build_windows_mingw.bat first.
  exit /b 1
)
if not exist bin\PacRipperCore.exe (
  echo ERROR: bin\PacRipperCore.exe is missing. Run build_windows_mingw.bat first.
  exit /b 1
)

if exist "%DEST%" rmdir /S /Q "%DEST%"
mkdir "%DEST%\bin" || exit /b 1

copy /Y bin\PacRipper.exe "%DEST%\bin\PacRipper.exe" >NUL || exit /b 1
copy /Y bin\PacRipperCore.exe "%DEST%\bin\PacRipperCore.exe" >NUL || exit /b 1

for %%D in (scripts semantic config docs) do (
  if exist "%%D" (
    xcopy "%%D" "%DEST%\%%D\" /E /I /Y /Q >NUL
    if errorlevel 1 exit /b 1
  )
)

for %%F in (README.md BUILDING.md CHANGELOG.md LICENSE THIRD_PARTY_NOTICES.md RELEASE_MANIFEST.txt SECURITY.md CITATION.cff) do (
  if exist "%%F" copy /Y "%%F" "%DEST%\%%F" >NUL
)

echo PacRipper standalone Windows package staged at:
echo   %DEST%
exit /b 0
