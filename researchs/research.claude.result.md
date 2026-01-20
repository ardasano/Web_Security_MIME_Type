Magic Byte Tabanlı Dosya Yükleme Güvenlik Testi
Dosya yükleme güvenlik sisteminizi kapsamlı test etmek için aşağıdaki senaryoları uygulayabilirsiniz:
✅ Valid (Geçerli) Test Senaryoları
Amaç: Sistemin meşru dosyaları doğru şekilde kabul ettiğini doğrulamak.
Test-1: Standart Görüntü Dosyaları

PNG dosyası yükleyin (magic bytes: 89 50 4E 47)
JPEG dosyası yükleyin (magic bytes: FF D8 FF)
GIF dosyası yükleyin (magic bytes: 47 49 46 38)
Beklenen sonuç: Tüm dosyalar başarıyla yüklenmeli

Test-2: Doğru Uzantı + Doğru Magic Byte

image.png uzantılı gerçek PNG dosyası
photo.jpg uzantılı gerçek JPEG dosyası
Beklenen sonuç: Sistem her iki kontrolü de geçmeli

Test-3: İzin Verilen Diğer Dosya Türleri

PDF (magic bytes: 25 50 44 46)
ZIP (magic bytes: 50 4B 03 04)
Beklenen sonuç: İzin listesindeki formatlar kabul edilmeli

❌ Invalid (Bypass Denemeleri) Test Senaryoları
Amaç: Sistemin bypass tekniklerine karşı dayanıklılığını test etmek.
Test-4: Uzantı Değiştirme (Extension Spoofing)

PHP dosyasını .png uzantısıyla kaydedin
Sadece uzantı kontrolü yapan sistemlerde bu geçer
Beklenen sonuç: Magic byte kontrolü nedeniyle REDDEDILMELI

Test-5: Magic Byte Ekleme (Prepending)

PHP shell kodunun başına PNG magic byte'ları ekleyin:

89 50 4E 47 0D 0A 1A 0A [PHP kodu buraya]

Beklenen sonuç: Dosya içerik analizi yapılıyorsa REDDEDILMELI

Test-6: Çift Uzantı (Double Extension)

malicious.php.png şeklinde dosya oluşturun
Beklenen sonuut: Sistem son uzantıyı mı yoksa tümünü mü kontrol ediyor test edin

Test-7: Null Byte Injection

malicious.php%00.png veya file.php\x00.png
Eski sistemlerde null byte sonrası göz ardı edilir
Beklenen sonuç: Modern sistemlerde REDDEDILMELI

Test-8: Content-Type Manipülasyonu

PHP dosyasını yüklerken HTTP başlığında Content-Type: image/png gönderin
Beklenen sonuç: Magic byte kontrolü varsa REDDEDILMELI

Test-9: Polyglot Dosyalar

Hem geçerli PNG hem de çalıştırılabilir PHP kodu içeren dosya
GIF + PHP kombinasyonu (GIF89a header + PHP kod)
Beklenen sonuç: Ciddi bir güvenlik riski, tespit edilmeli

Test-10: Case Sensitivity

.PHP, .PhP, .pHp gibi büyük/küçük harf varyasyonları
Beklenen sonuut: Tüm varyasyonlar REDDEDILMELI

Test-11: MIME Type Mismatch

JPEG magic byte'lı dosyayı .png uzantısıyla yükleyin
Beklenen sonuç: Uzantı-magic byte uyumsuzluğu tespit edilmeli

Test-12: Truncated/Corrupted Magic Bytes

Sadece ilk 2 byte PNG magic byte'ı içeren dosya
Beklenen sonuç: Eksik header kontrolü varsa REDDEDILMELI

🔍 Ek Kontrol Noktaları

Dosya Boyutu: Çok büyük veya 0 byte dosyalar
Karakter Seti: Türkçe karakter içeren dosya isimleri (dosya_adı.png)
Özel Karakterler: ../../../etc/passwd.png (path traversal)
Çoklu Yükleme: Aynı anda birden fazla dosya yükleme

🛡️ Güvenli Sistem Özellikleri
Sisteminiz şunları yapıyorsa güvenlidir:

✓ Magic byte ve uzantı birlikte kontrol ediliyor
✓ Dosya içeriği taranıyor (sadece header değil)
✓ Yüklenen dosyalar web root dışında saklanıyor
✓ Dosya isimleri yeniden adlandırılıyor (random hash)
✓ Çalıştırma izinleri kaldırılıyor

Bu testleri yaptıktan sonra hangi senaryolarda sorun bulduğunuzu paylaşırsanız, çözüm önerileri sunabilirim.
