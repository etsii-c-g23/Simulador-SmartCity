#!/bin/bash
echo "=========================================="
echo "   INICIANDO DEMOSTRACION DE SEGURIDAD"
echo "=========================================="

# 1. Abre el navegador automáticamente (compatible con Mac y Linux)
# Espera 2 segundos en segundo plano para dar tiempo a uvicorn a arrancar
(sleep 2 && (open http://127.0.0.1:8000 || xdg-open http://127.0.0.1:8000)) &

# 2. Inicia el servidor
uvicorn backend:app --reload