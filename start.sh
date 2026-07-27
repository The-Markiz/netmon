#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "=== NetMon — Network Monitor ==="

# Backend
echo "[1/3] Установка зависимостей backend..."
cd backend
pip install -r requirements.txt -q 2>/dev/null

# Frontend
echo "[2/3] Сборка frontend..."
cd ../frontend
npm install --silent 2>/dev/null
npm run build 2>/dev/null

# Запуск
echo "[3/3] Запуск сервера..."
cd ../backend
echo ""
echo "  NetMon: http://localhost:8000"
echo "  API docs: http://localhost:8000/docs"
echo ""
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
