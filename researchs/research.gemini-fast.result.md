MIME Type Güvenliği ve Magic Byte Analizi: Teknik Araştırma Raporu

Bu rapor, web güvenliğinin en kritik bileşenlerinden biri olan dosya türü doğrulama mekanizmalarını, Magic Byte (Sihirli Bayt) analizini ve bu sistemlerin nasıl atlatılabileceğine dair güvenlik açıklarını teknik derinlikle ele almaktadır.

1. Temel Çalışma Prensipleri
   MIME Type (Multipurpose Internet Mail Extensions)

MIME türleri, bir belgenin veya veri dosyasının doğasını ve formatını tanımlayan standartlaştırılmış etiketlerdir (Örn: image/jpeg, application/pdf).

İstemci Tarafı: Tarayıcı, sunucudan gelen Content-Type başlığına göre dosyayı nasıl işleyeceğine (render mı edecek, indirecek mi?) karar verir.

Sunucu Tarafı: Sunucu, yüklenen dosyanın izin verilen formatta olup olmadığını kontrol etmek için bu etiketi kullanır.

Magic Byte (File Signatures)

Magic Byte, bir dosyanın içeriğinin en başında yer alan ve dosya formatını benzersiz şekilde tanımlayan sabit bayt dizileridir. Dosya uzantısı değiştirilse bile bu baytlar değişmez.

Örnekler:

PNG: 89 50 4E 47 0D 0A 1A 0A (Hex)

PDF: 25 50 44 46 (Hex -> %PDF)

JPEG: FF D8 FF

Çalışma Akışı

Girdi: Kullanıcı bir dosya yükler.

Üstbilgi Kontrolü: Uygulama, HTTP isteğindeki Content-Type başlığını okur (Güvenilmezdir).

İçerik Analizi (Magic Byte): Sunucu tarafındaki bir kütüphane (örn. libmagic), dosyanın ilk birkaç baytını okuyarak gerçek türünü belirler.

Uzantı Doğrulama: Dosya uzantısı ile tespit edilen tür karşılaştırılır.

2. En İyi Uygulama Yöntemleri (Best Practices) ve Standartlar

Dosya yükleme güvenliğini sağlamak için "Savunma Derinliği" (Defense in Depth) stratejisi uygulanmalıdır:

Asla Kullanıcı Girdisine Güvenmeyin: HTTP Content-Type başlığı kullanıcı tarafından kolayca manipüle edilebilir. Doğrulama her zaman sunucu tarafında dosya içeriği üzerinden yapılmalıdır.

Dosyaları Yeniden Adlandırın: Yüklenen dosyaların orijinal adlarını rastgele oluşturulmuş (UUID gibi) isimlerle değiştirin. Bu, "Directory Traversal" ve "Direct Execution" risklerini azaltır.

Dosya Boyutu Sınırlandırması: Dosya boyutlarını hem sunucu hem de uygulama seviyesinde sınırlayarak DoS saldırılarını engelleyin.

Gelişmiş Başlık Yönetimi:

X-Content-Type-Options: nosniff: Tarayıcının dosya içeriğinden tür tahmini yapmasını engeller.

Content-Security-Policy (CSP): Yüklenen dosyaların script olarak çalıştırılmasını kısıtlar.

Yalıtılmış Depolama: Yüklenen dosyaları web kök dizininin (public_html) dışında ve script çalıştırma yetkisi olmayan bir dizinde/serviste (örn. AWS S3) saklayın.

3. Benzer Açık Kaynak Projeler ve Kütüphaneler

Analiz ve doğrulama için endüstri standardı haline gelmiş araçlar:

libmagic: Unix tabanlı file komutunun temelini oluşturan, en yaygın kullanılan Magic Byte kütüphanesidir.

Apache Tika: Çok çeşitli dosya formatlarından metadata ve metin çıkaran, kurumsal düzeyde bir analiz kütüphanesidir (Java).

Python-Magic: libmagic kütüphanesinin Python sarmalayıcısıdır.

File-type (Node.js): Binary buffer üzerinden dosya türü tespiti yapan popüler bir kütüphanedir.

CheckMATE: Dosya yükleme güvenlik testleri için kullanılan bir otomasyon aracıdır.

4. Kritik Yapılandırma Dosyaları ve Parametreleri
   Web Sunucuları

Nginx (mime.types): Dosya uzantılarının hangi MIME türü ile sunulacağını belirler.

code
Nginx
download
content_copy
expand_less
types {
text/html html htm shtml;
image/jpeg jpeg jpg;
}

Apache (.htaccess veya httpd.conf): AddType ve ForceType direktifleri ile MIME türleri yönetilir. Header set X-Content-Type-Options "nosniff" burada tanımlanmalıdır.

Programlama Dilleri

PHP (php.ini):

fileinfo eklentisi: Magic Byte analizi için aktifleştirilmelidir.

upload_max_filesize ve post_max_size: Boyut sınırları.

Python: magic.from_buffer(file.read(2048), magic=True) parametresi ile ilk 2048 bayt analiz edilir.

5. Güvenlik Açısından Kritik Noktalar (Bypass Teknikleri)

Saldırganlar, Magic Byte kontrollerini aşmak için çeşitli sofistike yöntemler kullanır:

1. Polyglot Files (Çok Dilli Dosyalar)

Bir dosyanın aynı anda iki farklı dosya formatı kuralına uygun olmasıdır.

Örnek: Bir dosyanın başı geçerli bir GIF Magic Byte'ı (GIF89a) ile başlar, ancak dosyanın yorum (comment) kısmında gizlenmiş zararlı bir PHP betiği barındırır. Sunucu bunu resim olarak kabul eder, ancak yanlış yapılandırma sonucu PHP olarak çalıştırılabilir.

2. Null Byte Injection

Bazı eski sistemlerde ve kütüphanelerde, dosya adındaki null karakteri (%00) işlemin sonlandırılmasına neden olur.

Saldırı: shell.php%00.jpg. Sistem .jpg uzantısını görür ve onaylar, ancak işletim sistemi dosyayı shell.php olarak kaydeder.

3. Metadata Manipülasyonu

EXIF verileri gibi metadata alanlarına JavaScript kodları enjekte edilerek XSS (Cross-Site Scripting) saldırıları gerçekleştirilebilir. Tarayıcı dosyayı render ederken bu kodları çalıştırabilir.

4. MIME Sniffing İstismarı

Tarayıcılar (özellikle eski Internet Explorer sürümleri), sunucunun gönderdiği Content-Type başlığına güvenmek yerine dosyanın içeriğine bakarak tür tahmini yapmaya çalışır.

Saldırı: Bir saldırgan .txt uzantılı bir dosya içine HTML/Script yükler. Tarayıcı "sniffing" yaparak bunu HTML olarak yorumlar ve XSS tetiklenir.

5. Content Manipulation (İçerik Manipülasyonu)

Magic Byte'lar doğru olsa bile, dosyanın ilerleyen kısımlarına (örneğin bir resmin sonuna) eklenen zararlı kodlar, bazı sunucu taraflı işleyiciler (ImageMagick vb.) tarafından tetiklenebilir.

Kaynaklar

OWASP: File Upload Cheat Sheet

IANA: Media Types Registry

Gary Kessler: File Signatures (Magic Bytes) Database

Mozilla: MIME Sniffing Standard

PayloadsAllTheThings: File Upload Attacks Research

Bu rapor, siber güvenlik araştırmacıları ve sistem mimarları için rehber niteliğinde hazırlanmıştır. Uygulama aşamasında her katmanda doğrulama yapılması önerilir.
