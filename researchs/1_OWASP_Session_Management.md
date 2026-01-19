# OWASP Oturum Yönetimi ve Çerez Güvenliği Araştırması

## 1. Kritik Çerez (Cookie) Bayrakları
Web güvenliğinde oturum çerezlerinin çalınmasını önlemek için şu bayraklar zorunludur:
- **HttpOnly:** Çerezlerin JavaScript (`document.cookie`) ile okunmasını engeller. XSS saldırılarında oturumun çalınmasını önler.
- **Secure:** Çerezin sadece şifreli (HTTPS) bağlantılarda iletilmesini sağlar. Man-in-the-Middle (MitM) saldırılarını zorlaştırır.
- **SameSite:** `Strict` veya `Lax` olarak ayarlanmalıdır. CSRF (Siteler Arası İstek Sahteciliği) saldırılarına karşı korur.

## 2. Oturum Çalma (Session Hijacking) & Fixation
- **Session Fixation:** Saldırganın kurbanın oturum ID'sini önceden belirlemesi. 
  - *Çözüm/Test:* Kullanıcı giriş yaptıktan (login) sonra sunucu **yeni** bir Session ID vermelidir. Eski ID geçerliliğini yitirmelidir.
- **Session Prediction:** Oturum ID'lerinin tahmin edilebilir (ardışık sayılar, zaman damgası vb.) olması.
  - *Çözüm/Test:* ID'ler kriptografik olarak rastgele ve yeterli uzunlukta (min 128 bit) olmalıdır.

## 3. Oturum Zaman Aşımı (Timeout)
- **Idle Timeout:** Kullanıcı işlem yapmadığında oturumun sonlanması (Örn: 15-30 dk).
- **Absolute Timeout:** Ne kadar aktif olursa olsun oturumun belirli bir süre sonra (Örn: 24 saat) zorla sonlandırılması.
