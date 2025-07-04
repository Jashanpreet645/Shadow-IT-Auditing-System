@echo off
title Company Audit Panel

:: This is the main entry point of the script.
if exist deployment-info.json (
    goto main_menu
) else (
    goto first_time_setup
)

:first_time_setup
cls
echo ===================================================
echo      WELCOME - FIRST TIME SETUP REQUIRED
echo ===================================================
echo.
echo The smart contract has not been deployed yet.
echo You must deploy the contract before you can perform any other actions.
echo.
echo Please make sure the 'Blockchain Node' window is running.
echo.
pause
cls
echo --- Deploying Contract ---
call npm run deploy
echo.

:: --- THE FIX IS HERE ---
:: Add a 1-second delay to give the OS time to write the file to disk.
echo Waiting for file system to update...
ping 127.0.0.1 -n 2 > nul
:: --- END OF FIX ---

:: After deployment and delay, check again.
if exist deployment-info.json (
    echo --- Deployment Successful! ---
    pause
    goto main_menu
) else (
    echo --- DEPLOYMENT FAILED. Please check for errors above. ---
    pause
    goto exit
)


:main_menu
cls
echo ===================================================
echo            COMPANY AUDIT WORKFLOW
echo ===================================================
echo.
echo Contract has been deployed. Please choose an option:
echo.
echo   1. Run Weekly Audit (Generate logs and submit root)
echo   2. Generate Auditor Proof Package
echo.
echo   3. Re-Deploy Contract (Advanced - Resets the system)
echo   4. Exit
echo.
echo ===================================================
    
set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" goto weekly_audit
if "%choice%"=="2" goto generate_proof
if "%choice%"=="3" goto deploy_advanced
if "%choice%"=="4" goto exit

echo Invalid choice.
pause
goto main_menu

:weekly_audit
cls
echo --- Running Weekly Audit ---
call npm run run:weekly_audit
echo.
echo --- Weekly Audit Finished ---
pause
goto main_menu

:generate_proof
cls
echo --- Generate Auditor Proof Package ---
echo.
set /p logfile="Enter the log file name (e.g., process_log_2.json): "
if "%logfile%"=="" (
    echo No filename entered. Returning to menu.
    pause
    goto main_menu
)
call npm run generate:proof -- %logfile%
echo.
echo --- Proof Generation Finished ---
pause
goto main_menu

:deploy_advanced
cls
echo --- WARNING ---
echo Re-deploying will create a new contract and will require
echo you to update any external tools with the new address.
echo.
set /p confirm="Are you sure you want to re-deploy? (y/n): "
if /i "%confirm%"=="y" (
    del deployment-info.json
    goto first_time_setup
) else (
    echo Re-deployment cancelled.
    pause
    goto main_menu
)

:exit
exit