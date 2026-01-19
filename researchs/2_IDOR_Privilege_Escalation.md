# IDOR (Insecure Direct Object Reference) ve Yetki Yükseltme

## Mantık
Saldırgan, URL veya parametredeki bir ID değerini değiştirerek başkasının verisine erişir.
- **Örnek:** `site.com/profile?user_id=100` isteğindeki 100'ü 101 yaparak başka profili görme.

## Test Yöntemi (Algoritma)
1. **Kullanıcı A** olarak giriş yap ve kendine ait bir kaynağın (Örn: Fatura No: 555) detayını iste.
2. **Kullanıcı B** olarak giriş yap.
3. Kullanıcı B'nin oturumunu kullanarak, Kullanıcı A'nın kaynağına (Fatura No: 555) istek at.
4. **Sonuç:** Erişim başarılıysa (HTTP 200 OK) -> **ZAFİYET VAR**. Erişim reddedilirse (HTTP 403/401) -> **GÜVENLİ**.
