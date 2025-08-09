@echo off
echo ========================================
echo   🚀 Deploy Automático a GitHub 🚀
echo ========================================
echo.

:: 1. Traer cambios remotos
echo 🔄 Haciendo pull de GitHub...
git pull origin main
echo.

:: 2. Pedir mensaje del commit
set /p msg="✏️ Escribe el mensaje del commit: "

:: 3. Agregar y commitear cambios
git add .
git commit -m "%msg%"

:: 4. Subir cambios a GitHub
echo 🚀 Subiendo cambios a GitHub...
git push origin main

echo ✅ ¡Deploy completado correctamente!
pause
