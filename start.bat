@echo off
title Simulador IoT - Paper G-23
echo ==========================================
echo    INICIANDO DEMOSTRACION DE SEGURIDAD
echo ==========================================

:: 1. Abre el navegador automáticamente
echo Abriendo interfaz web...
start http://127.0.0.1:8000

:: 2. Inicia el servidor
echo Iniciando Backend Python...
python -m uvicorn backend:app --reload

:: Esto mantiene la ventana abierta si hay un error
pause