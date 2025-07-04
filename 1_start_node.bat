@echo off
title Blockchain Node (Keep this window running)
echo ===================================================
echo.
echo      STARTING LOCAL BLOCKCHAIN NODE...
echo.
echo ===================================================
echo.

:: Run the Hardhat node command
call npx hardhat node

echo.
echo Node has stopped. You can close this window.
pause