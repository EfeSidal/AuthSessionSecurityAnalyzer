# Research Result for gemini-pro

# Auth Session Security Analyzer: Teknik Araştırma Raporu

**Tarih:** 18 Ocak 2026
**Konu:** Oturum Güvenliği ve Yetkilendirme Analiz Teknolojileri
**Kapsam:** Çalışma Prensipleri, En İyi Uygulamalar, Araçlar ve Kritik Yapılandırmalar.

## 1. Temel Çalışma Prensipleri

Auth Session Security Analyzer araçları, temel olarak **"Traffic Replay"** (Trafik Tekrarı) ve **"Entropy Analysis"** (Entropi Analizi) yöntemlerini kullanır.

### A. Yetkilendirme Analizi (Authorization Logic)
Bu araçlar (Örn: Burp Suite Auth Analyzer), uygulamanın erişim kontrollerini (Access Control) şu mantıkla test eder:

1.  **Oturum Kaydı:** Farklı yetki seviyelerine sahip kullanıcıların (Admin, Standart Kullanıcı, Anonim) oturum anahtarları (Cookie/Token) araca tanıtılır.
2.  **Trafik Tekrarı (Replay):** Yüksek yetkili bir kullanıcı (Admin) ile gezinirken yapılan istekler yakalanır. Araç, bu istekleri arka planda **düşük yetkili kullanıcının** oturum anahtarı ile değiştirerek sunucuya tekrar gönderir.
3.  **Diffing (Karşılaştırma):** Orijinal (Admin) yanıtı ile test (Düşük Yetkili) yanıtı karşılaştırılır.
    * *Başarılı Saldırı:* Eğer düşük yetkili kullanıcıya `200 OK` dönerse veya dönen veri boyutu admin ile aynıysa, bir **IDOR (Insecure Direct Object Reference)** veya **BOLA (Broken Object Level Authorization)** zafiyeti tespit edilmiş olur.

### B. Oturum Güvenliği Analizi (Session Strength)
Oturum anahtarlarının (Session ID) güvenliği, matematiksel rastgelelik testleri ile ölçülür.

* **Entropi Analizi:** Token'ın tahmin edilebilirliğini ölçer.
* **İstatistiksel Testler:** FIPS 140-2 gibi standart testler uygulanarak, üretilen token'ların bir örüntü (pattern) izleyip izlemediği kontrol edilir.

## 2. En İyi Uygulama Yöntemleri (Best Practices)

Endüstri standartları büyük ölçüde **OWASP ASVS (Application Security Verification Standard)** tarafından belirlenmiştir.

### Endüstri Standartları
* **Minimum Entropi:** Oturum kimlikleri en az **128-bit** rastgelelik içermelidir.
* **Cookie Güvenlik Bayrakları:**
    * `HttpOnly`: JavaScript ile erişimi engeller (XSS koruması).
    * `Secure`: Sadece HTTPS üzerinden iletimi zorunlar.
    * `SameSite`: CSRF saldırılarını hafifletir (`Strict` veya `Lax`).
* **Oturum Zaman Aşımları:**
    * *Idle Timeout:* 15-30 dakika hareketsizlikte oturum kapanmalıdır.
    * *Absolute Timeout:* Ne kadar aktif olursa olsun, belirli bir süre sonra (örn. 12-24 saat) oturum zorla yenilenmelidir.

> **Not:** Kullanıcı giriş yaptığında (Login) veya şifre değiştirdiğinde mevcut Session ID **mutlaka** imha edilmeli ve yenisi oluşturulmalıdır. Bu, **Session Fixation** saldırılarını önler.

## 3. Benzer Açık Kaynak Projeler ve Rakipler

Piyasada bu analizleri yapan başlıca araçlar:

| Araç Adı | Tür | Açıklama |
| :--- | :--- | :--- |
| **Auth Analyzer** | Burp Extension | (Lider Araç) Otomatik trafik tekrarı yapar. Dinamik parametreleri güncelleyebilir. |
| **AuthMatrix** | Burp Extension | Yetki matrisi tabanlıdır. Roller ve Endpoint'ler arası erişimi test eder. |
| **Authorize** | Burp Extension | Eski ama popüler bir araçtır. Otomatik IDOR tespiti yapar. |
| **OWASP ZAP** | Açık Kaynak | ZAP içerisindeki "Access Control Testing" modülü. |
| **Burp Sequencer** | Dahili Araç | Sadece oturum token'larının rastgeleliğini analiz eder. |

## 4. Kritik Yapılandırma Dosyaları ve Parametreleri

### A. Web Sunucuları
* **Nginx (`nginx.conf`):**
    ```nginx
    proxy_cookie_path / "/; HTTPOnly; Secure";
    ```
* **Apache (`httpd.conf`):**
    ```apache
    Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure
    ```

### B. Uygulama Çerçeveleri
* **Node.js (Express-session):**
    ```javascript
    app.use(session({
      secret: process.env.SESSION_SECRET,
      name: 'sessionId',
      cookie: { httpOnly: true, secure: true, sameSite: 'strict' }
    }));
    ```
* **PHP (`php.ini`):**
    * `session.cookie_httponly = 1`
    * `session.cookie_secure = 1`
    * `session.use_strict_mode = 1`

## 5. Güvenlik Açısından Kritik Noktalar

1.  **Session Fixation:** Saldırganın belirlediği ID ile kurbanın oturum açması. *Çözüm:* Login sonrası `session_regenerate_id()`.
2.  **Yetersiz Sonlandırma:** Logout sonrası sunucudaki oturumun silinmemesi.
3.  **Hassas Veri İfşası:** JWT payload içerisinde hassas verilerin şifresiz taşınması.
4.  **Zayıf Algoritma:** JWT için `HS256` yerine `RS256` kullanılmaması veya `None` algoritma zafiyeti.
