# 🔍 Derin Araştırma Raporu: MIME Type Güvenlik Analizi

**Tarih:** 19.01.2026
**Konu:** Web Uygulamalarında Dosya Yükleme Güvenliği ve Bypass Teknikleri
**Araştırma Yöntemi:** Literatür Taraması ve Teknik Dokümantasyon İncelemesi

---

## 1. Problem Tanımı (The Problem)

Web uygulamalarında kullanıcıdan dosya alırken (Upload), sunucular genellikle sadece dosya uzantısına (Extension) bakar. Ancak bu yöntem güvenli değildir.

- **MIME Sniffing:** Tarayıcıların, dosya uzantısı yanlış olsa bile içeriği tahmin edip çalıştırması durumudur.
- **Extension Spoofing:** Saldırganın zararlı bir `.exe` dosyasını `.jpg` olarak yeniden adlandırıp sisteme yüklemesi.

## 2. Teknik Analiz ve Çözüm (Technical Specs)

Yapılan araştırmalar sonucunda (OWASP File Upload Cheat Sheet ve Python Dokümantasyonu), en güvenli yöntemin **"Magic Byte" (Sihirli Bayt)** analizi olduğu doğrulanmıştır.

### Magic Bytes Nedir?

Her dosya formatı, dosyanın en başında (Header) kendine has hex kodları taşır.

- **JPEG:** `FF D8 FF ...`
- **PNG:** `89 50 4E 47 ...`
- **PDF:** `25 50 44 46 ...`

Bu kodlar değiştirilemez imzalardır. Dosya adı `resim.jpg` olsa bile, eğer header `4D 5A` (EXE formatı) ile başlıyorsa, bu dosya zararlıdır.

## 3. Kaynak ve Kütüphane Seçimi (Verification)

Projede kullanılacak yöntemler için aşağıdaki kaynaklar karşılaştırıldı:

- **Yöntem A (Sadece Uzantı):** Yetersiz. Kolayca bypass edilebilir.
- **Yöntem B (imghdr kütüphanesi):** Eski ve sınırlı format desteği var.
- **Yöntem C (python-magic / libmagic):** **Seçilen Yöntem.**
  - _Sebep:_ Unix tabanlı `file` komutunu temel alır, endüstri standardıdır ve binary analizi yapar.

## 4. Doğrulama Metodolojisi (Verification System)

Geliştirilen proje şu senaryolarla test edilecektir:

1.  **Valid File:** Gerçek PNG/JPG yüklemesi -> **Başarılı olmalı.**
2.  **Fake File:** Uzantısı değiştirilmiş Text dosyası -> **Engellenmeli.**
3.  **Polyglot:** İçinde hem resim hem kod barındıran dosyalar -> **Analiz edilmeli.**

---

_Bu rapor, proje geliştirme sürecinde yapay zeka araçları ve teknik dokümanlar referans alınarak oluşturulmuştur._
