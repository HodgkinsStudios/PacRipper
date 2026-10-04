@echo off
rem PacRipper native MinGW build for Windows
rem Created by Jacob Hodgkins
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

if not exist bin mkdir bin
if not exist obj\windows mkdir obj\windows

if defined MINGW_CXX (
  set "CXX=%MINGW_CXX%"
) else (
  set "CXX=g++"
)

"%CXX%" --version >NUL 2>NUL
if errorlevel 1 (
  echo ERROR: MinGW g++ was not found. Use a Code::Blocks MinGW terminal, add MinGW\bin to PATH, or set MINGW_CXX.
  exit /b 1
)

set "COMMON=-std=c++17 -O2 -DNDEBUG -Wall -Wextra -Wpedantic -Werror"
set "INCLUDES=-Isrc"
set "LINK_RUNTIME=-static-libgcc -static-libstdc++ -lstdc++fs"

del /Q obj\windows\*.o 2>NUL
set "OBJS="
set /A OBJINDEX=0

for /F "usebackq tokens=* delims=" %%S in ("config\core_sources.txt") do (
  if not "%%S"=="" (
    set /A OBJINDEX+=1
    set "SRC=%%S"
    set "SRC=!SRC:/=\!"
    set "OBJ=obj\windows\core_!OBJINDEX!.o"
    echo [CXX] !SRC!
    "%CXX%" %COMMON% %INCLUDES% -c "!SRC!" -o "!OBJ!"
    if errorlevel 1 exit /b 1
    set "OBJS=!OBJS! "!OBJ!""
  )
)

echo [CXX] src\pacripper_core_main.cpp
"%CXX%" %COMMON% %INCLUDES% -c src\pacripper_core_main.cpp -o obj\windows\pacripper_core_main.o
if errorlevel 1 exit /b 1

echo [LINK] bin\PacRipperCore.exe
"%CXX%" -std=c++17 -O2 -o bin\PacRipperCore.exe !OBJS! obj\windows\pacripper_core_main.o %LINK_RUNTIME%
if errorlevel 1 exit /b 1

echo [LINK] bin\PacRipper.exe
"%CXX%" %COMMON% src\main.cpp -o bin\PacRipper.exe %LINK_RUNTIME%
if errorlevel 1 exit /b 1

echo [TEST] PacRipper.exe --version
bin\PacRipper.exe --version
if errorlevel 1 exit /b 1

echo PacRipper Windows MinGW build: PASS
exit /b 0
