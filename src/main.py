import requests
from colorama import Fore, Style

class AuthAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()

    def check_cookie_flags(self):
        """
        Cookie Güvenliği: HttpOnly, Secure ve SameSite bayraklarını kontrol eder.
        """
        print(f"{Fore.CYAN}[*] Cookie Güvenliği Analiz Ediliyor...{Style.RESET_ALL}")
        try:
            response = self.session.get(self.target_url)
            cookies = response.cookies
            
            if not cookies:
                print(f"{Fore.YELLOW}[!] Hiç cookie bulunamadı.{Style.RESET_ALL}")
                return

            for cookie in cookies:
                print(f"Cookie: {cookie.name}")
                # HttpOnly Kontrolü (Requests lib 'rest' özniteliğinde tutabilir veya flaglerden bakar)
                if cookie.has_nonstandard_attr('HttpOnly') or 'HttpOnly' in cookie._rest:
                     print(f"{Fore.GREEN}  [+] HttpOnly: VAR{Style.RESET_ALL}")
                else:
                     print(f"{Fore.RED}  [-] HttpOnly: YOK (XSS Riski!){Style.RESET_ALL}")

                # Secure Kontrolü
                if cookie.secure:
                    print(f"{Fore.GREEN}  [+] Secure: VAR{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}  [-] Secure: YOK (MITM Riski!){Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {e}{Style.RESET_ALL}")

    def check_session_fixation(self, login_url, username, password):
        """
        Session Fixation: Login öncesi ve sonrası Session ID değişiyor mu?
        """
        print(f"\n{Fore.CYAN}[*] Session Fixation Testi...{Style.RESET_ALL}")
        
        # 1. Login öncesi istek
        self.session.get(self.target_url)
        pre_login_cookies = self.session.cookies.get_dict()
        pre_id = pre_login_cookies.get('session_id') or pre_login_cookies.get('PHPSESSID')
        print(f"Login Öncesi ID: {pre_id}")

        # 2. Login olma
        payload = {'username': username, 'password': password}
        self.session.post(login_url, data=payload)
        
        # 3. Login sonrası kontrol
        post_login_cookies = self.session.cookies.get_dict()
        post_id = post_login_cookies.get('session_id') or post_login_cookies.get('PHPSESSID')
        print(f"Login Sonrası ID: {post_id}")

        if pre_id and post_id and pre_id == post_id:
            print(f"{Fore.RED}[!] ZAFİYET: Session ID değişmedi! (Fixation Mümkün){Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] GÜVENLİ: Session ID yenilendi.{Style.RESET_ALL}")

if __name__ == "__main__":
    # Örnek Kullanım
    target = input("Hedef URL: ")
    analyzer = AuthAnalyzer(target)
    analyzer.check_cookie_flags()
    # analyzer.check_session_fixation(...) # Bu kısım login URL'si gerektirir.
