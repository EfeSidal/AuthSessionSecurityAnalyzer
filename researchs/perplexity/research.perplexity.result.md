# Research Result for perplexity

Auth Analyzer'ın kritik yapılandırma dosyaları ve parametreleri, Burp Suite entegrasyonuyla yönetilir ve her biri belirli test senaryolarını optimize eder. En iyi uygulamalar, OWASP standartlarıyla uyumlu şekilde uygulanır. Aşağıda her unsuru tek tek detaylandırıyoruz.

## Sessions Panel Yapılandırması
Sessions panelinde "New Session" ile yeni oturum profili oluşturun; buraya cookie, Authorization header veya custom token'lar ekleyin (örneğin, Cookie: sessionid=high_priv_user). Bu, düşük/yüksek yetki seviyelerini temsil eder; authentication'sız session için boş bırakın. Yanlış ekleme bypass tespiti bozar, her session'ı gerçek tarayıcı trafiğinden yakalayın. 

## Parametre Tanımlama Özelliği
"Add Parameter" butonuyla extraction mode seçin: Auto Extract Set-Cookie (session cookie'leri otomatik çeker), JSON/HTML parsing veya Static Value girin. From String To String moduyla body'den dinamik değerler (CSRF token) kesip değiştirir; Prompt for Input manuel override sağlar. Bu, replay'lerde dinamik auth'u korur, yoksa false positive artar. 

## Filtreleme Parametreleri
HTTP method filtreleri (GET/POST, OPTIONS hariç) ve path exclusions ayarlayın; örneğin /api/admin hariç tutun. Request Viewer'da status filtreleri (bypassed only) gürültüyü azaltır. CPU yükünü yönetmek için scope'u sitemap'ten sınırlayın.
## Extender ve Genel Ayarlar
Burp Extender > Extensions > Auth Analyzer yükleyin; Options'ta memory limit (örn. 4GB) ve verbose logging ayarlayın. JAR dosyası PortSwigger BApp Store'dan iner, manuel config yok. Scanner integration'da low impact seçin.
