@echo off
chcp 65001 >nul
set NETMON_SUBNET=192.168.31.0/24
cd /d "%~dp0backend"
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
