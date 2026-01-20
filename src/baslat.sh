#!/bin/bash
echo "--- [LINUX OTOMASYON BASLATILIYOR] ---"
echo "[1/2] Gerekli kutuphaneler yukleniyor..."

# Linux'ta python-magic-bin yerine python-magic ve libmagic kullanilir
sudo apt-get update
sudo apt-get install libmagic1 -y
pip install flask python-magic

echo "[2/2] Proje baslatiliyor..."
python3 app.py