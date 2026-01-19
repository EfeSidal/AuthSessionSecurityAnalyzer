# 🛡️ Auth Session Security Analyzer

![Language](https://img.shields.io/badge/Language-Python-3776AB?logo=python&logoColor=white)
![Security Standard](https://img.shields.io/badge/Standard-OWASP-black)
![Category](https://img.shields.io/badge/Category-SecOps%20%7C%20Pentesting-red)
![License](https://img.shields.io/badge/License-MIT-green)

**Auth Session Security Analyzer**, modern web uygulamalarındaki oturum yönetimi (Session Management) mekanizmalarını derinlemesine analiz eden, güvenlik açıklarını tespit etmek ve raporlamak için geliştirilmiş bir sızma testi (pentesting) aracıdır.

---

## 📑 İçindekiler

- [Proje Hakkında](#-proje-hakkında)
- [Özellikler ve Analiz Yetenekleri](#-özellikler-ve-analiz-yetenekleri)
- [Teknik Metodoloji](#-teknik-metodoloji)
- [Kurulum](#-kurulum)
- [Kullanım](#-kullanım)
- [Yasal Uyarı](#-yasal-uyarı)

---

## 🎯 Proje Hakkında

Web güvenliğinin en kritik katmanlarından biri olan "Oturum Yönetimi" (Session Management), saldırganların kullanıcı hesaplarını ele geçirmesi için en sık hedef aldığı alandır. 

Bu araç, **HTTP Cookies** ve **JWT (JSON Web Token)** yapılarını kullanan uygulamalarda; oturum çalma, yetki yükseltme ve konfigürasyon hatalarını **OWASP (Open Web Application Security Project)** standartlarına göre otomatik olarak test eder.

---

## 🚀 Özellikler ve Analiz Yetenekleri

Proje, aşağıdaki 4 ana güvenlik disiplini üzerinde özelleşmiş testler uygular:

### 1. 🕵️‍♂️ Oturum Çalma (Session Hijacking) Analizi
Saldırganların bir oturumu ele geçirme senaryolarını simüle eder.
- **Entropi Analizi:** Session ID'nin rastgeleliğini ve tahmin edilebilirliğini (Predictability) matematiksel olarak hesaplar.
- **XSS Vektör Kontrolü:** Session token'ların Cross-Site Scripting (XSS) saldırılarıyla çalınmaya müsait olup olmadığını denetler.

### 2. 🍪 Gelişmiş Cookie Güvenliği Denetimi
Sunucu tarafından set edilen çerezlerin güvenlik bayraklarını (flags) tarar:
- **`HttpOnly`:** İstemci taraflı scriptlerin çereze erişimini engelliyor mu?
- **`Secure`:** Çerez sadece HTTPS üzerinden mi iletiliyor?
- **`SameSite`:** CSRF saldırılarına karşı `Strict` veya `Lax` modunda yapılandırılmış mı?

### 3. ⏱️ Timeout (Zaman Aşımı) Analizi
Oturum yaşam döngüsünü kontrol eder:
- **Idle Timeout:** Kullanıcı işlem yapmadığında oturumun düşme süresi.
- **Absolute Timeout:** Oturumun zorunlu sonlanma süresinin güvenli aralıkta olup olmadığı.

### 4. 🛡️ Yetki Yükseltme ve İzolasyon (Privilege Escalation)
Farklı kullanıcı rolleri arasındaki sınırları test eder:
- **IDOR (Insecure Direct Object References):** Bir kullanıcının session verisiyle başka bir kullanıcının verisine erişip erişemediğinin kontrolü.
- **Horizontal & Vertical Escalation:** Normal kullanıcıdan Admin yetkisine geçiş denemeleri.

---

## 🛠️ Teknik Metodoloji

Bu araç, analizlerini gerçekleştirirken aşağıdaki protokol ve standartları referans alır:

| Standart / Protokol | Açıklama |
| :--- | :--- |
| **OWASP Session Management** | Küresel uygulama güvenliği topluluğunun belirlediği "en iyi pratikler" ve güvenlik kontrol listesi. |
| **HTTP Cookies** | Geleneksel oturum yönetiminde kullanılan çerez yapılarının header analizi. |
| **JSON Web Tokens (JWT)** | Token tabanlı kimlik doğrulamada imza (signature) ve payload güvenliği kontrolü. |

---

## 📥 Kurulum

Projeyi yerel makinenize klonlayın ve gerekli bağımlılıkları yükleyin.

```bash
# Repoyu klonlayın
git clone [https://github.com/EfeSidal/AuthSessionSecurityAnalyzer.git](https://github.com/EfeSidal/AuthSessionSecurityAnalyzer.git)

# Proje dizinine girin
cd AuthSessionSecurityAnalyzer

# Gerekli Python kütüphanelerini yükleyin
pip install -r requirements.txt

```

---

## 💻 Kullanım

Aracı terminal üzerinden hedef URL veya cookie verisi ile başlatabilirsiniz.

**Temel Tarama:**

```bash
python main.py --target [https://ornek-uygulama.com](https://ornek-uygulama.com) --scan basic

```

**Detaylı Cookie Analizi:**

```bash
python main.py --target [https://ornek-uygulama.com](https://ornek-uygulama.com) --check-cookies

```

**JWT Token Testi:**

```bash
python main.py --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." --mode deep-scan

```

---

## ⚠️ Yasal Uyarı

> **Dikkat:** Bu yazılım yalnızca **eğitim** ve **izinli güvenlik testleri** amacıyla geliştirilmiştir. Sahibi olmadığınız veya açık yazılı izninizin bulunmadığı sistemlerde kullanılması yasa dışıdır ve suç teşkil edebilir. Geliştirici, bu aracın kötü niyetli kullanımından doğacak sonuçlardan sorumlu tutulamaz.

---

<div align="center">
Developed by <b>EfeSidal</b> for Safer Web
</div>


- Öğrenci Numarası: *2420191004*
