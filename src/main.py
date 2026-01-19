import requests
import sys
from colorama import Fore, Style, init

# strip=False komutu, "Dosyaya yazıyor olsak bile RENKLERİ GÖSTER" demektir.
init(autoreset=True, strip=False)

class AuthAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url.strip()
        self.session = requests.Session()
        # Chrome maskesi
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def check_cookie_flags(self):
        print(f"{Fore.CYAN}[*] Cookie Güvenliği Analiz Ediliyor...{Style.RESET_ALL}")
        try:
            response = self.session.get(self.target_url, timeout=10, allow_redirects=True)
            cookies = response.cookies
            
            if not cookies:
                print(f"{Fore.YELLOW}[!] Hiç cookie bulunamadı.{Style.RESET_ALL}")
                return

            for cookie in cookies:
                print(f"Cookie: {Fore.MAGENTA}{cookie.name}{Style.RESET_ALL}")
                
                if cookie.has_nonstandard_attr('HttpOnly') or 'HttpOnly' in cookie._rest:
                     print(f"{Fore.GREEN}  [+] HttpOnly: VAR (Güvenli){Style.RESET_ALL}")
                else:
                     print(f"{Fore.RED}  [-] HttpOnly: YOK (XSS Riski!){Style.RESET_ALL}")

                if cookie.secure:
                    print(f"{Fore.GREEN}  [+] Secure: VAR (Güvenli){Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}  [-] Secure: YOK (MITM Riski!){Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Bağlantı Hatası: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Hedef URL: ")
    
    analyzer = AuthAnalyzer(target)
    analyzer.check_cookie_flags()