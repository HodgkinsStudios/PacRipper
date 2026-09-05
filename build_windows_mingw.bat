@echo off
rem PacRipper MinGW build for Windows
rem Created by Jacob Hodgkins
setlocal EnableDelayedExpansion
cd /d "%~dp0"
if not exist bin mkdir bin
if not exist obj\windows mkdir obj\windows

where g++ >NUL 2>NUL
if errorlevel 1 (
  echo ERROR: g++ was not found in PATH. Use a Code::Blocks MinGW terminal or add MinGW\bin to PATH.
  exit /b 1
)

set OBJS=
for /F "usebackq tokens=* delims=" %%S in ("config\core_sources.txt") do (
  if not "%%S"=="" (
    set SRC=%%S
    set SRC=!SRC:/=\!
    set OBJ=obj\windows\%%~nS.o
    echo [CXX] !SRC!
    g++ -std=c++17 -O2 -DNDEBUG -Isrc -c "!SRC!" -o "!OBJ!"
    if errorlevel 1 exit /b 1
    set OBJS=!OBJS! "!OBJ!"
  )
)

echo [CXX] src\pacripper_core_main.cpp
g++ -std=c++17 -O2 -DNDEBUG -Isrc -c src\pacripper_core_main.cpp -o obj\windows\pacripper_core_main.o
if errorlevel 1 exit /b 1

echo [LINK] bin\PacRipperCore.exe
g++ -std=c++17 -O2 -o bin\PacRipperCore.exe !OBJS! obj\windows\pacripper_core_main.o -lstdc++fs
if errorlevel 1 exit /b 1

echo [LINK] bin\PacRipper.exe
g++ -std=c++17 -O2 -DNDEBUG src\main.cpp -o bin\PacRipper.exe -lstdc++fs
if errorlevel 1 exit /b 1

echo PacRipper Windows MinGW build: PASS
exit /b 0
