@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo 正在启动 NIDS 仪表盘服务...
echo 启动后请在浏览器打开 http://127.0.0.1:5000
echo 关闭此窗口即可停止服务。
echo.
"C:\Users\deokee\.workbuddy-ai\binaries\python\envs\default\Scripts\python.exe" backend/api.py
pause
