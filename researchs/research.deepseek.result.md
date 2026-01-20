@echo off
title Web_Security_MIME_Type
echo ========================================
echo Web Security - MIME Type Control
echo ========================================
echo.

echo [1] Sistem baslatiliyor...
echo.

echo [2] Gerekli kutuphaneler kontrol ediliyor...
pip install flask python-magic-bin --quiet
if %errorlevel% neq 0 (
echo [HATA] Kutuphaneler yuklenirken sorun olustu!
pause
exit /b 1
)
echo [OK] Kutuphaneler basariyla yuklendi.
echo.

echo [3] Flask uygulamasi baslatiliyor...
echo -> Tarayici otomatik acilacak: http://127.0.0.1:5000
echo -> Durdurmak icin CTRL+C tuslarina basin.
echo.
echo ========================================
echo.

python app.py

if %errorlevel% neq 0 (
echo.
echo [HATA] Uygulama baslatilamadi!
echo app.py dosyasini kontrol edin.
pause
)
