import requests
from bs4 import BeautifulSoup
import time
import os
import sys
import threading
from datetime import datetime
from dotenv import load_dotenv
from colorama import Fore, Style, init
import subprocess

# Initialize Colorama
init(autoreset=True)

# Load environment variables
load_dotenv()

# Global variables
scan_results = []
reports_dir = "reports"
summary = {
    "mentions": 0,
    "leaks": 0,
    "darkweb": "Skipped"
}

# Check and create reports folder
if not os.path.exists(reports_dir):
    os.makedirs(reports_dir)

# Try to auto-launch Tor if available
def launch_tor():
    try:
        subprocess.Popen(['tor'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(10)  # Give Tor time to start
        return True
    except Exception:
        return False

# Check if Tor is running
def is_tor_running():
    try:
        proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        requests.get('http://check.torproject.org', proxies=proxies, timeout=5)
        return True
    except:
        return False

TOR_AVAILABLE = is_tor_running()
if not TOR_AVAILABLE:
    print(f"{Fore.YELLOW}⚡ Tor not detected. Trying to launch Tor...")
    if launch_tor():
        print(f"{Fore.GREEN}✅ Tor launched successfully!")
        TOR_AVAILABLE = is_tor_running()
    else:
        print(f"{Fore.RED}⚠️ Failed to auto-launch Tor. Dark Web search will be skipped.")

# Spinner animation
def spinner_animation(task_description, duration=2):
    spinner = ['|', '/', '-', '\\']
    sys.stdout.write(f"{Fore.CYAN}{task_description} ")
    for _ in range(duration * 5):
        for symbol in spinner:
            sys.stdout.write(symbol)
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write('\b')
    print(f"{Fore.GREEN}Done!")

# LeakCheck search
def leakcheck_search(email):
    try:
        url = f"https://leakcheck.net/api/public?check={email}"
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            if data.get("found"):
                scan_results.append(f"\n[LeakCheck] Possible leaks found for {email}:")
                for source in data.get("sources", []):
                    site = source.get('name', 'Unknown site')
                    date = source.get('date', 'Unknown date')
                    exposed_data = source.get('data', '')
                    result_text = f" - Site: {site} | Date: {date} | Data: {exposed_data}"
                    scan_results.append(result_text)
                    if 'password' in exposed_data.lower():
                        summary["leaks"] += 1
                print(f"{Fore.RED}[+] LeakCheck leaks found.")
            else:
                print(f"{Fore.YELLOW}[-] No leaks found on LeakCheck.")
        else:
            print(f"{Fore.RED}❌ Error: HTTP {response.status_code} from LeakCheck.")
    except Exception as e:
        print(f"{Fore.RED}❌ LeakCheck Search Error: {str(e)}")

# Google Search
def google_search(email):
    try:
        query = f'"{email}" "password"'
        url = f"https://www.google.com/search?q={query}"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            search_results = soup.find_all('div', class_='BNeawe vvjwJb AP7Wnd')

            if search_results:
                scan_results.append(f"\n[Google] Possible public mentions:")
                for idx, result in enumerate(search_results[:5], 1):
                    scan_results.append(f" {idx}. {result.text}")
                    summary["mentions"] += 1
                print(f"{Fore.GREEN}[+] Google search completed.")
            else:
                print(f"{Fore.YELLOW}[-] No mentions found on Google.")
        else:
            print(f"{Fore.RED}❌ Error: HTTP {response.status_code} from Google.")
    except Exception as e:
        print(f"{Fore.RED}❌ Google Search Error: {str(e)}")

# DuckDuckGo Search
def duckduckgo_search(email):
    try:
        query = f'"{email}" "password"'
        url = f"https://lite.duckduckgo.com/lite/?q={query}"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            results = soup.find_all('a')

            real_results = []
            for result in results:
                link_text = result.text.strip()
                if link_text and "duckduckgo" not in link_text.lower():
                    real_results.append(link_text)

            if real_results:
                scan_results.append(f"\n[DuckDuckGo] Possible public mentions:")
                for idx, result in enumerate(real_results[:5], 1):
                    scan_results.append(f" {idx}. {result}")
                    summary["mentions"] += 1
                print(f"{Fore.GREEN}[+] DuckDuckGo search completed.")
            else:
                print(f"{Fore.YELLOW}[-] No mentions found on DuckDuckGo.")
        else:
            print(f"{Fore.RED}❌ Error: HTTP {response.status_code} from DuckDuckGo.")
    except Exception as e:
        print(f"{Fore.RED}❌ DuckDuckGo Search Error: {str(e)}")

# Scylla.sh or backup Deep Web Search
def search_scylla(email):
    try:
        url = f"https://scylla.sh/search?query={email}"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            results = soup.find_all('code')

            found = False
            for result in results:
                text = result.text
                if email in text and ':' in text:
                    scan_results.append(f"\n[Scylla.sh] 🔑 Leak found: {text.strip()}")
                    found = True
                    summary["leaks"] += 1
            if found:
                print(f"{Fore.RED}[+] Scylla.sh leaks found.")
            else:
                print(f"{Fore.YELLOW}[-] No leaks found on Scylla.sh.")
        else:
            print(f"{Fore.RED}❌ Error: HTTP {response.status_code} from Scylla.sh. Trying backup...")
    except Exception as e:
        print(f"{Fore.RED}❌ Scylla.sh Search Error: {str(e)}")

# Dark Web Search
def search_darkweb(email):
    if not TOR_AVAILABLE:
        summary["darkweb"] = "Skipped"
        print(f"{Fore.YELLOW}⚡ Skipping Dark Web search (Tor not running).")
        return

    try:
        proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        onion_sites = [
            "http://pastedihrz5wduczduo3rvwprmpvhsl33jnwokicv5yzu6lbynr2pid.onion/",
            "http://pastedwebec6k6exmclne4qgxs7psp7jvsmpa5s3fe32fiyc4s3id.onion/"
        ]

        found = False
        for site in onion_sites:
            response = requests.get(site, proxies=proxies, timeout=15)
            if response.status_code == 200 and email in response.text:
                snippet = response.text.split(email)[0][-50:] + email + response.text.split(email)[1][:50]
                scan_results.append(f"\n[Dark Web] 🔑 Leak found on {site}: ...{snippet}...")
                found = True
                summary["leaks"] += 1
                summary["darkweb"] = "Searched"
                print(f"{Fore.RED}[+] Leak found on Dark Web site: {site}")
                break
        if not found:
            print(f"{Fore.YELLOW}[-] No leaks found on Dark Web.")
            summary["darkweb"] = "Searched"
    except Exception as e:
        print(f"{Fore.RED}❌ Dark Web Search Error: {str(e)}")
        summary["darkweb"] = "Failed"

# Save results if user wants
def save_results(email):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    filename = f"{reports_dir}/{email}_{timestamp}.txt"
    with open(filename, 'w', encoding='utf-8') as f:
        for line in scan_results:
            f.write(line + "\n")
        f.write("\n---\n")
        f.write(f"Summary:\n- {summary['mentions']} public mentions\n- {summary['leaks']} possible leaks\n- Dark Web search: {summary['darkweb']}\n")
    print(f"{Fore.GREEN}✅ Report saved to {filename}")

# Main function
def main():
    print(f"{Fore.MAGENTA}========================================")
    print("      🛡️ Deep & Dark Web Email Scanner 🛡️")
    print("========================================\n")

    while True:
        email = input(f"{Fore.CYAN}Enter your email address: ").strip()

        if '@' not in email or '.' not in email:
            print(f"{Fore.RED}⚠️ Invalid email format. Please try again.\n")
            continue

        spinner_animation("Starting full scan...", duration=2)

        scan_results.clear()
        summary.update({"mentions": 0, "leaks": 0, "darkweb": "Skipped"})

        # Launch parallel threads
        threads = [
            threading.Thread(target=google_search, args=(email,)),
            threading.Thread(target=duckduckgo_search, args=(email,)),
            threading.Thread(target=leakcheck_search, args=(email,)),
            threading.Thread(target=search_scylla, args=(email,)),
            threading.Thread(target=search_darkweb, args=(email,))
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        print("\n".join(scan_results))
        print(f"\n{Fore.YELLOW}--- Scan Summary ---")
        print(f"- {summary['mentions']} public mentions found")
        print(f"- {summary['leaks']} possible leaks detected")
        print(f"- Dark Web search: {summary['darkweb']}")

        save = input(f"\n{Fore.CYAN}Would you like to save a full report? (Y/N): ").strip().lower()
        if save == 'y':
            save_results(email)

        again = input(f"{Fore.CYAN}Would you like to scan another email? (Y/N): ").strip().lower()
        if again != 'y':
            print(f"{Fore.GREEN}Goodbye! Stay safe online. 🛡️")
            break

if __name__ == "__main__":
    main()
