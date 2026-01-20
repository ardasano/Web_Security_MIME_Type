İstenilen detaylı teknik araştırma raporunu aşağıda sunuyorum. Bu rapor, MIME türü güvenliği, Magic Byte (Dosya İmzası) analizi ve güvenli dosya yükleme süreçlerini kapsamaktadır.

MIME Type Security & Magic Byte Analysis: Teknik Araştırma Raporu
1. Giriş ve Temel Çalışma Prensipleri

Web uygulamalarında dosya yükleme özellikleri, siber güvenlik açısından en kritik saldırı yüzeylerinden biridir. Sistemlerin yüklenen dosyanın zararsız (örneğin bir resim) olduğunu doğrulaması gerekir. Bu doğrulama üç ana katmanda gerçekleşir: Uzantı (Extension), MIME Type (Content-Type) ve Magic Bytes (File Signature).

A. MIME Type (Multipurpose Internet Mail Extensions)

MIME türü, dosyaların internet üzerinde nasıl işleneceğini belirten bir standarttır.

Çalışma Prensibi: İstemci (tarayıcı), bir dosya yüklerken HTTP başlığında Content-Type: image/jpeg gibi bir bilgi gönderir.

Güvenlik Zafiyeti: Bu bilgi tamamen istemci taraflıdır ve manipüle edilebilir. Bir saldırgan, malware.php dosyasını gönderirken HTTP isteğini yakalayıp (Burp Suite vb. ile) Content-Type başlığını image/jpeg olarak değiştirebilir. Sunucu sadece buna bakarsa kandırılmış olur.

B. Magic Bytes (Dosya İmzası)

Her dosya formatı, dosyanın en başında (header) formatı tanımlayan benzersiz onaltılık (hexadecimal) bayt dizilerine sahiptir. Buna "Magic Number" veya "Magic Bytes" denir.

Çalışma Prensibi: İşletim sistemi veya kütüphane, dosya uzantısına bakmaksızın dosyanın ilk birkaç baytını okuyarak türünü tespit eder.

Örnekler:

JPEG: FF D8 FF ...

PNG: 89 50 4E 47 0D 0A 1A 0A

GIF89a: 47 49 46 38 39 61

PDF: 25 50 44 46 (%PDF)

EXE/DLL: 4D 5A (MZ)

2. Güvenlik Açısından Kritik Noktalar (Bypass Teknikleri)

Saldırganlar, sunucudaki filtreleri atlatmak (WAF/Filter Bypass) ve sunucuda kod çalıştırmak (RCE) için aşağıdaki teknikleri kullanırlar.

A. MIME Type Spoofing

En basit tekniktir. Saldırgan shell.php yükler ancak HTTP isteğinde Content-Type: application/x-php yerine Content-Type: image/png gönderir. Sunucu sadece header kontrolü yapıyorsa dosya kabul edilir.

B. Magic Byte Injection (Fake Headers)

Sunucu Magic Byte kontrolü yapıyorsa, saldırgan zararlı dosyanın (PHP/ASPX) en başına geçerli bir resim imzasını ekler.

Senaryo: Bir PHP dosyasının başına GIF89a yazılır. Sunucu dosyayı okuduğunda "Bu bir GIF dosyası" der, ancak dosya .php uzantısı ile kaydedilirse PHP yorumlayıcısı GIF89a kısmını görmezden gelip sonraki zararlı kodu çalıştırabilir.

C. Polyglot Dosyalar

Polyglot, birden fazla dosya formatı olarak geçerli olan dosyalardır.

Örnek: Hem geçerli bir JPEG resmi hem de geçerli bir JavaScript veya PHP kodu içeren dosyalar.

Teknik: Saldırganlar, JPEG formatının "Comment" (Yorum) veya EXIF veri alanlarına PHP kodu (<?php system($_GET['cmd']); ?>) gömerler. Dosya sunucuda resim olarak doğrulanır ancak bir şekilde include edilirse kod çalışır.

D. Uzantı Manipülasyonları (Double Extensions & Null Byte)

shell.php.jpg: Apache'nin eski yapılandırmalarında (Double Extension zafiyeti), sunucu .jpg'yi tanımazsa soldan sağa okuyarak .php olarak işleyebilir.

shell.php%00.jpg: Null byte injection (Eski sistemlerde), dosya adı okuma işleminin %00'da sonlanmasına neden olur ve dosya shell.php olarak kaydedilir.

3. En İyi Uygulama Yöntemleri (Best Practices)

Güvenli bir dosya yükleme mekanizması için "Derinlemesine Savunma" (Defense in Depth) ilkesi uygulanmalıdır.

İstemci Verisine Güvenmeyin: Asla sadece Content-Type header'ına veya dosya uzantısına güvenmeyin.

Magic Byte Doğrulaması: Sunucu tarafında dosyanın içeriğini okuyarak Magic Byte analizi yapın.

Dosya Uzantısını Beyaz Liste (Allowlist) ile Kontrol Edin: Sadece izin verilen uzantılara (.jpg, .png, .pdf) izin verin. Asla karalisteleme (Blocklist: .php, .exe engelleme) yapmayın; atlatılması kolaydır (.phtml, .php5 vb.).

Dosya Adını Rastgeleleştirin (Renaming): Yüklenen dosyayı orijinal adıyla saklamayın. md5(microtime()) gibi bir yöntemle rastgele bir isim verin ve uzantıyı kendiniz atayın.

Görüntüleri Yeniden İşleyin (Image Re-processing): Yüklenen resimleri ImageMagick veya GD Library gibi araçlarla yeniden boyutlandırın veya formatını değiştirin. Bu işlem, dosya içine gizlenmiş (Steganography/Polyglot) zararlı kodları ve EXIF verilerini temizler (strip).

Web Root Dışında Depolama: Mümkünse dosyaları web sunucusunun erişebileceği public dizinlerin dışında (/var/www/uploads yerine S3 Bucket veya veritabanı) saklayın.

Çalıştırma İzinlerini Kapatın: Yükleme klasöründe script çalıştırma izinlerini (Execute Permission) kapatın.

4. Kritik Yapılandırma Dosyaları ve Parametreleri

Web sunucularında dosya yükleme güvenliği için kritik konfigürasyonlar şunlardır:

Apache (.htaccess veya httpd.conf)

Yükleme dizininde script çalıştırılmasını engellemek için:

code
Apache
download
content_copy
expand_less
<Directory "/var/www/html/uploads">
    # PHP motorunu bu dizin için kapatır
    php_flag engine off 
    # Tüm dosyaların işlenmesini engeller, sadece indirilmelerini sağlar
    ForceType application/octet-stream
    <FilesMatch "(?i)\.(php|pl|py|jsp|asp|sh|cgi)$">
        Order Deny,Allow
        Deny from All
    </FilesMatch>
</Directory>
Nginx (nginx.conf)

Yükleme dizininde PHP yürütmesini engellemek için:

code
Nginx
download
content_copy
expand_less
location /uploads/ {
    # Bu dizindeki herhangi bir dosyayı PHP soketine yönlendirmeyi kapatır
    location ~ \.php$ {
        return 403;
    }
}
PHP (php.ini)

file_uploads = On (Gerekmiyorsa Off yapılmalı)

upload_tmp_dir (Geçici dosyaların tutulduğu yer, web root dışında olmalı)

upload_max_filesize ve post_max_size (DoS saldırılarını önlemek için limitler makul tutulmalı)

5. Benzer Açık Kaynak Projeler ve Kullanılan Kütüphaneler

Endüstride MIME ve Magic Byte tespiti için kullanılan standart kütüphaneler şunlardır:

Sistem Seviyesi

libmagic: Unix/Linux sistemlerdeki standart file komutunun arkasındaki kütüphanedir. En güvenilir kaynaklardan biridir. Veritabanı genellikle /usr/share/misc/magic.mgc konumundadır.

Programlama Dilleri İçin Kütüphaneler

Python:

python-magic: Libmagic'in Python sarmalayıcısıdır (wrapper). Endüstri standardıdır.

Kullanım: magic.from_file('upload.tmp', mime=True)

PHP:

finfo_open(FILEINFO_MIME_TYPE): PHP'nin yerleşik ve önerilen dosya bilgi sınıfıdır. Libmagic veritabanını kullanır.

Kullanım:

code
PHP
download
content_copy
expand_less
$finfo = new finfo(FILEINFO_MIME_TYPE);
$type = $finfo->file($_FILES['image']['tmp_name']);

Uyarı: Eski mime_content_type() fonksiyonu deprecated (kullanımdan kalkmış) olabilir veya yetersiz kalabilir.

Go (Golang):

net/http.DetectContentType: Dosyanın ilk 512 baytını okuyarak türü tahmin eder.

Node.js:

file-type (Sindre Sorhus): Dosya imzasını (Buffer) kontrol ederek türü belirleyen popüler bir npm paketidir.

Java:

Apache Tika: İçerik analizi ve metadata çıkarma konusunda en kapsamlı kütüphanedir.

6. Sonuç ve Referanslar

MIME türü güvenliği, sadece "dosya uzantısını kontrol etme" işleminden çok daha karmaşıktır. Güvenlik, doğrulama (validation), temizleme (sanitization) ve izolasyon (isolation) süreçlerinin birleşimi ile sağlanır. Sadece Magic Byte kontrolü yetersizdir; dosya içeriğinin yeniden işlenmesi (re-rendering) en kesin çözümlerden biridir.

Kaynaklar:

OWASP: "File Upload Cheat Sheet" - owasp.org

PHP Documentation: "Fileinfo Functions" - php.net

MITRE ATT&CK: "T1036.008 - Masquerading: Masquerade File Type"

PortSwigger (Burp Suite): "File upload vulnerabilities" - portswigger.net

Gary Kessler: "File Signature Table" (Magic Bytes referans listesi).
