import os
import magic
from flask import Flask, request, render_template

app = Flask(__name__)

YUKLEME_YERİ = 'uploads'
os.makedirs(YUKLEME_YERİ, exist_ok=True) #klasor yoksa olustur
app.config['UPLOAD_FOLDER'] = YUKLEME_YERİ

# sadece bu uzantilara izin verdik
IZIN_LISTESI = {
    'image/jpeg': ['.jpg', '.jpeg'],
    'image/png': ['.png'],
    'application/pdf': ['.pdf']
}

def sistemi_test_et():
    print("--- [SISTEM TESTI BASLADI] ---")
    if os.path.exists(YUKLEME_YERİ):
        print("[OK] Yukleme klasoru var.")
    else:
        print("[HATA] Klasor yok, olusturulmali!")
    
    try:
        deneme = magic.Magic(mime=True)
        print("[OK] Magic kutuphanesi yuklu.")
    except:
        print("[KRITIK HATA] Magic kutuphanesi calismiyor, pip install python-magic-bin yapilmali.")
    print("--- [TEST BITTI] ---\n")

# --- ASIL GUVENLIK ISLEMI ---
def dosyayi_tarat(dosya_nesnesi, dosya_ismi):
    baslangic_kodlari = dosya_nesnesi.read(2048)
    dosya_nesnesi.seek(0) #bunu yapmazsak dosya bos veya bozuk olarak kaydedilir

    # kutuphane ile gercek turu bulma
    gercek_tur = magic.from_buffer(baslangic_kodlari, mime=True)
    
    print(f"DEBUG: Dosya Adi: {dosya_ismi} | Bulunan Tur: {gercek_tur}")

    if gercek_tur not in IZIN_LISTESI:
        return False, f"HATA: {gercek_tur} turune izin vermiyoruz."

    # bypass kontrol
    uzanti = os.path.splitext(dosya_ismi)[1].lower()
    
    uygun_uzantilar = IZIN_LISTESI[gercek_tur]
    
    if uzanti not in uygun_uzantilar:
        return False, "SAHTECILIK: Dosya uzantisi ile icerigi tutmuyor! (Fake Dosya)"

    return True, "Dosya temiz, yuklendi."

@app.route('/', methods=['GET', 'POST'])
def ana_sayfa():
    mesaj = ""
    renk = ""

    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('index.html', mesaj="Dosya secmediniz.")
        
        gelen_dosya = request.files['file']
        
        if gelen_dosya.filename == '':
            return render_template('index.html', mesaj="Dosya ismi bos.")

        if gelen_dosya:
            #guvenlik taramasi
            sonuc, aciklama = dosyayi_tarat(gelen_dosya.stream, gelen_dosya.filename)
            
            if sonuc == True:
                gelen_dosya.save(os.path.join(app.config['UPLOAD_FOLDER'], gelen_dosya.filename))
                mesaj = "BASARILI: " + aciklama
                renk = "yesil"
            else:
                mesaj = "ENGELLENDI: " + aciklama
                renk = "kirmizi"

    return render_template('index.html', mesaj=mesaj, renk=renk)

if __name__ == "__main__":
    sistemi_test_et()
    app.run(debug=True)