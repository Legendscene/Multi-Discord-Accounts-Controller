@echo off
title Bulk Member Importer
cd /d "%~dp0"
if not exist "node_modules\" (
  echo Installing dependencies...
  npm install
)
node src/index.js
echo.
echo Press any key to exit...
pause >nul
