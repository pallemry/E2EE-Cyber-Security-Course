@echo off
REM Start the server
start cmd /k python server.py

REM Start the first client with +111111111 argument
start cmd /k python client.py +111111111

REM Start the second client with +222222222 argument
start cmd /k python client.py +222222222

REM Keep the batch file window open
pause