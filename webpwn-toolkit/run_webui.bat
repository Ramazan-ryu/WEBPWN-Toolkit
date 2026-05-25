@echo off
chcp 65001 >nul
set PYTHONUTF8=1
echo.
echo  WebPwn Web UI - Starting...
echo  Open your browser at: http://localhost:5000
echo.
python web_server.py
pause
