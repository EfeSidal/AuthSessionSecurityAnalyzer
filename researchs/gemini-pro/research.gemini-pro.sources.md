# Sources for gemini-pro

# Kaynaklar ve Referanslar

Bu araştırma aşağıdaki endüstri standartları, araç dokümantasyonları ve güvenlik rehberleri temel alınarak oluşturulmuştur.

## 📘 Standartlar ve Rehberler
1.  **OWASP ASVS (Application Security Verification Standard)**
    * [OWASP ASVS Project Page](https://owasp.org/www-project-application-security-verification-standard/)
    * *Bölüm V3: Session Management Verification Requirements*
2.  **OWASP Session Management Cheat Sheet**
    * [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
3.  **RFC 6265 (HTTP State Management Mechanism)**
    * [IETF RFC 6265 - Cookies](https://datatracker.ietf.org/doc/html/rfc6265)

## 🛠 Araçlar ve Dokümantasyonlar
1.  **PortSwigger (Burp Suite) Extensions**
    * [Auth Analyzer (GitHub)](https://github.com/simor91/Auth-Analyzer)
    * [AuthMatrix (GitHub)](https://github.com/SecurityInnovation/AuthMatrix)
    * [Authorize (GitHub)](https://github.com/Qu33nB/Authorize)
2.  **Express-Session (Node.js)**
    * [Express-session (npm)](https://www.npmjs.com/package/express-session)
    * [Express-session (GitHub)](https://github.com/expressjs/session)
3.  **PHP Manual**
    * [PHP Session Security](https://www.php.net/manual/en/session.security.php)
    * [Session Management Functions](https://www.php.net/manual/en/book.session.php)

## 🧠 Teknik Kavramlar ve Zafiyet Tanımları (CWE)
* **IDOR:** [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* **Session Fixation:** [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
* **Entropy Requirements:** [NIST SP 800-63B (Digital Identity Guidelines)](https://pages.nist.gov/800-63-3/sp800-63b.html)
