@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo === NetMon — Network Monitor ===

echo [1/3] Установка зависимостей backend...
cd backend
pip install -r requirements.txt -q 2>nul

echo [2/3] Сборка frontend...
cd ..\frontend
call npm install --silent 2>nul
call npm run build 2>nul

echo [3/3] Запуск сервера...
cd ..\backend
echo.
echo   NetMon: http://localhost:8000
echo   API docs: http://localhost:8000/docs
echo.
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
