@echo off
title Web_Security_MIME_Type
color 0a
echo ==========================================
echo [1/2] Gerekli kutuphaneler yukleniyor...
echo ==========================================
pip install flask python-magic-bin

echo.
echo ==========================================
echo [2/2] Proje baslatiliyor...
echo ==========================================
python app.py
pause