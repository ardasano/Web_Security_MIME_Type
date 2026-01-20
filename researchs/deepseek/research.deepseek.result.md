MIME Type Security & Magic Byte Analizi: Teknik Araştırma Raporu
1. Temel Çalışma Prensipleri
1.1 MIME Type Kavramı
MIME (Multipurpose Internet Mail Extensions) tipi, internet üzerinde gönderilen dosyaların türünü tanımlamak için kullanılan standart bir tanımlayıcıdır. Formatı type/subtype şeklindedir (örn: image/jpeg, application/pdf).

Çalışma Mekanizması:

Dosya uzantısı bazlı tespit

Magic byte (imza byte'ları) analizi

HTTP Content-Type başlıkları

İçerik sniffing (tarayıcıların içeriği analiz etmesi)

1.2 Magic Byte Analizi
Her dosya formatının dosyanın başlangıcında bulunan benzersiz byte dizileri vardır. Örnekler:

Format	Magic Bytes (Hex)	ASCII Karşılığı
JPEG	FF D8 FF	ÿØÿ
PNG	89 50 4E 47	‰PNG
PDF	25 50 44 46	%PDF
GIF	47 49 46 38	GIF8
ZIP	50 4B 03 04	PK..
1.3 Güvenlik Bağlamında Önemi
File Upload Güvenliği: Kötü niyetli dosyaların yüklenmesini engelleme

Content Sniffing Saldırıları: Tarayıcıların yanlış MIME type'ı yorumlaması

MIME Sniffing Bypass: Saldırganların MIME tespitini atlatma teknikleri

2. En İyi Uygulama Yöntemleri ve Endüstri Standartları
2.1 Savunma Katmanları Yaklaşımı
OWASP Önerileri:

Beyaz Liste Yaklaşımı: Sadece izin verilen MIME tiplerini kabul et

Dosya Adı Doğrulama: Uzantı kontrolü + normalizasyon

Magic Byte Doğrulaması: Dosya içeriğinin imza byte'larını kontrol et

Dosya Boyutu Limiti: Maksimum boyut sınırlaması

Virus/Malware Taraması: Antivirus entegrasyonu

2.2 HTTP Başlığı Güvenliği
http
# Güvenli yapılandırma örnekleri
X-Content-Type-Options: nosniff
Content-Disposition: attachment; filename="safe-file.pdf"
Content-Security-Policy: default-src 'self'
2.3 Endüstri Standartları
RFC 7578: MIME-based file upload standartları

RFC 6266: Content-Disposition başlığı

OWASP File Upload Cheat Sheet: Güvenli dosya yükleme rehberi

NIST SP 800-162: Attribute-Based Access Control

3. Benzer Açık Kaynak Projeler ve Kütüphaneler
3.1 Magic Byte Tespit Kütüphaneleri
Python:

python-magic (libmagic binding)

filetype (saf Python implementasyonu)

python
import magic
mime = magic.Magic(mime=True)
file_type = mime.from_file("file.pdf")
Node.js:

file-type (popüler, bakımı aktif)

mmmagic (libmagic binding)

javascript
const FileType = require('file-type');
const type = await FileType.fromFile('file.png');
PHP:

finfo (built-in extension)

mime-content-type fonksiyonu

php
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $filepath);
Java:

Apache Tika (kapsamlı MIME tespiti)

jmimemagic (Java portu)

3.2 Tam Kapsamlı Güvenlik Çözümleri
ModSecurity: Web uygulama güvenlik duvarı

ClamAV: Açık kaynak antivirus

VirusTotal API: Çoklu motor tarama

Sandbox Çözümleri: Cuckoo Sandbox, ANY.RUN

4. Kritik Yapılandırma Dosyaları ve Parametreleri
4.1 Web Sunucu Konfigürasyonları
Nginx:

nginx
# MIME type mapping
types {
    application/pdf pdf;
    image/jpeg jpg jpeg;
    text/html html htm;
}

# Güvenlik başlıkları
add_header X-Content-Type-Options "nosniff" always;
Apache:

apache
<FilesMatch "\.(php|phtml|phar)$">
    ForceType application/octet-stream
    Header set Content-Disposition attachment
</FilesMatch>

<IfModule mod_mime.c>
    AddType application/pdf .pdf
    AddType image/jpeg .jpg .jpeg
</IfModule>
4.2 Uygulama Seviyesi Konfigürasyon
yaml
# Örnek güvenlik yapılandırması
file_upload:
  allowed_mime_types:
    - image/jpeg
    - image/png
    - application/pdf
  max_file_size: 10485760  # 10MB
  magic_bytes_validation: true
  virus_scanning: true
  sanitize_filename: true
  randomize_filename: true
4.3 Database MIME Type Mapping
sql
-- Güvenli MIME type mapping tablosu
CREATE TABLE allowed_mime_types (
    id INT PRIMARY KEY,
    mime_type VARCHAR(100),
    allowed_extensions TEXT[],
    max_size INT,
    is_active BOOLEAN DEFAULT true
);
5. Güvenlik Açısından Kritik Noktalar ve Bypass Teknikleri
5.1 Yaygın Bypass Teknikleri
1. Double Extension Bypass:

text
malicious.php.jpg  → Sunucu .jpg, PHP .php olarak işler
2. Magic Byte Manipülasyonu:

bash
# JPEG magic byte ekleyerek PHP dosyasını gizleme
echo -e "\xff\xd8\xff\xe0<?php system($_GET['cmd']); ?>" > shell.jpg.php
3. Content-Type Spoofing:

http
POST /upload.php HTTP/1.1
Content-Type: image/jpeg  # Sahte başlık

<?php system($_GET['cmd']); ?>
4. Null Byte Injection:

text
shell.php%00.jpg  → Bazı sistemlerde null byte'dan sonrasını ignore eder
5. Case Manipulation:

text
shell.PHp  → Case-sensitive olmayan sistemlerde bypass
6. Unicode/Normalization Bypass:

text
shell.pʰp  → Unicode homoglif saldırıları
5.2 Güvenlik Zafiyetleri ve Karşı Önlemler
Zafiyet 1: Yetersiz Magic Byte Kontrolü

Risk: Sadece ilk few byte kontrolü

Çözüm: Multiple signature kontrolü + dosya boyunca tarama

Zafiyet 2: Race Conditions

Risk: Upload sonrası işlemler arası zamanlama saldırıları

Çözüm: Atomic işlemler, dosya permission yönetimi

Zafiyet 3: File Parsing Vulnerabilities

Risk: PDF, JPEG vb. parser zafiyetleri

Çözüm: Sandbox ortamında parsing, güncel kütüphaneler

Zafiyet 4: MIME Type Confusion

Risk: Birden fazla MIME type'ı olan dosyalar

Çözüm: Strict matching, secondary validation

5.3 Gelişmiş Savunma Teknikleri
1. File Content Re-rendering:

python
# Upload edilen görselleri yeniden render et
from PIL import Image
def sanitize_image(input_path, output_path):
    img = Image.open(input_path)
    img.save(output_path, optimize=True, quality=85)
2. File Type Quarantine:

bash
# Karantina mekanizması
upload/          # Public upload dizini
quarantine/      # İşlenmemiş dosyalar
processed/       # Validasyon sonrası
3. Behavioral Analysis:

javascript
// Dosya davranış analizi
const analyzeBehavior = async (filePath) => {
    const metrics = {
        entropy: calculateEntropy(filePath),
        structure: analyzeFileStructure(filePath),
        suspiciousPatterns: scanForPatterns(filePath)
    };
    return scoreRisk(metrics);
};
4. Multi-Engine Validation:

python
# Çoklu doğrulama katmanı
def validate_file(file_path):
    validations = [
        magic_byte_validation(file_path),
        extension_validation(file_path),
        size_validation(file_path),
        content_analysis(file_path),
        virus_total_check(file_path)  # API call
    ]
    return all(validations)
6. Kaynaklar ve Referanslar
6.1 Resmi Dokümantasyon
IANA MIME Types: https://www.iana.org/assignments/media-types/

RFC 6838: MIME Type Specifications

OWASP File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload

Mozilla Security Guidelines: https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types

6.2 Araçlar ve Kütüphaneler
libmagic: https://github.com/file/file (C implementation)

Apache Tika: https://tika.apache.org/

File Type Detect: https://github.com/sindresorhus/file-type

TrID File Identifier: http://mark0.net/soft-trid-e.html

6.3 Güvenlik Araştırmaları
PortSwigger File Upload: https://portswigger.net/web-security/file-upload

SANS Institute Whitepapers: File Upload Security

BlackHat Presentations: "Bypassing File Upload Restrictions"

Bug Bounty Reports: HackerOne disclosed reports on file upload vulnerabilities

6.4 Akademik Çalışmalar
"A Comprehensive Study of File Upload Vulnerabilities" - IEEE 2022

"Magic Byte Analysis for Digital Forensics" - Digital Investigation Journal

"Content-Type Spoofing Attacks" - ACM Conference on Computer and Communications Security

Sonuç
MIME type güvenliği ve magic byte analizi, modern web uygulama güvenliğinin kritik bileşenlerindendir. Savunma stratejisi olarak defense in depth yaklaşımı benimsemeli, birden fazla doğrulama katmanı uygulanmalıdır. Saldırgan teknikleri sürekli evrimleştiğinden, güvenlik kontrollerinin düzenli güncellenmesi ve proaktif test edilmesi esastır.

Önerilen Güvenlik Modeli:

Input validation (client + server side)

Magic byte + MIME type doğrulaması

File sanitization/reconstruction

Behavioral analysis

Sandbox execution (şüpheli dosyalar için)

Continuous monitoring ve log analysis

Bu katmanlı yaklaşım, dosya yükleme mekanizmalarında ortaya çıkabilecek güvenlik açıklarını minimize edecek ve uygulamanın genel güvenlik postürünü güçlendirecektir.# Research Result for deepseek
