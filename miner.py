import requests
import hashlib
import time
import argparse
from time import gmtime, strftime
from colorama import init, Fore, Style

init(autoreset=True)

FINAL_HASH_RATE_DISPLAY = False
difficulty_bits = 25
target = 2**(256 - difficulty_bits)

success, fail = 0, 0

def sha256(data):
    """Compute SHA-256 hash."""
    return hashlib.sha256(data.encode()).hexdigest()

def format_hashrate(hashes_per_second):
    """Convert hash rate to appropriate units (H/s, KH/s, MH/s, GH/s)."""
    if hashes_per_second >= 1_000_000_000:
        return f"{hashes_per_second / 1_000_000_000:.2f} GH/s"
    elif hashes_per_second >= 1_000_000:
        return f"{hashes_per_second / 1_000_000:.2f} MH/s"
    elif hashes_per_second >= 1_000:
        return f"{hashes_per_second / 1_000:.2f} KH/s"
    else:
        return f"{hashes_per_second:.2f} H/s"

def mine_block(wallet, worker, server_url):
    """Fetch last block, mine new block, and submit it."""
    global success, fail
    
    try:
        response = requests.get(f"{server_url}/get_block", timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"[{strftime('%Y-%m-%d %H:%M:%S', gmtime())}] {Fore.RED}Error connecting to server: {e}{Style.RESET_ALL}", flush=True)
        return

    last_block = response.json()
    
    index = last_block["index"] + 1
    previous_hash = last_block["hash"]
    timestamp = time.time()
    
    nonce = 0
    hash_attempts = 0
    start_time = time.time()
    last_print_time = start_time  # Track last printed time for updates
    max_hashrate = 0  # Track the highest hash rate achieved
    
    print(f"[{strftime('%Y-%m-%d %H:%M:%S', gmtime())}] {Fore.MAGENTA}new job{Style.RESET_ALL} from {server_url} index {index}{Style.RESET_ALL}")
    
    while True:
        block_string = f"{index}{timestamp}{previous_hash}{nonce}"
        block_hash = sha256(block_string)

        if int(block_hash, 16) < target:
            break
        
        nonce += 1
        hash_attempts += 1

        # Print speed and max hash rate every 30 seconds
        current_time = time.time()
        elapsed_time = current_time - start_time
        if current_time - last_print_time >= 30:
            hash_rate = hash_attempts / elapsed_time if elapsed_time > 0 else 0
            max_hashrate = max(max_hashrate, hash_rate)
            print(f"[{strftime('%Y-%m-%d %H:%M:%S', gmtime())}] speed {Fore.CYAN}{format_hashrate(hash_rate)}{Style.RESET_ALL} max {Fore.CYAN}{format_hashrate(max_hashrate)}{Style.RESET_ALL}")
            last_print_time = current_time

    elapsed_time = time.time() - start_time
    final_hash_rate = hash_attempts / elapsed_time if elapsed_time > 0 else 0

    new_block = {
        "index": index,
        "timestamp": timestamp,
        "previous_hash": previous_hash,
        "nonce": nonce,
        "hash": block_hash,
        "miner": wallet,
        "worker": worker  # Include mining rig name
    }

    try:
        response = requests.post(f"{server_url}/submit_block", json=new_block, timeout=10)
        response.raise_for_status()
        success += 1
        print(f"[{strftime('%Y-%m-%d %H:%M:%S', gmtime())}] {Fore.GREEN}accepted{Style.RESET_ALL} ({success}/{fail}) | Block ID: {index} | {Fore.LIGHTCYAN_EX}({wallet}/{worker})", flush=True)
    except requests.RequestException as e:
        fail += 1
        print(f"[{strftime('%Y-%m-%d %H:%M:%S', gmtime())}] {Fore.RED}rejected{Style.RESET_ALL} ({success}/{fail}) | Block ID: {index} | {Fore.LIGHTCYAN_EX}({wallet}/{worker}) | Error: {e}", flush=True)

    if FINAL_HASH_RATE_DISPLAY:
        print(f"[{strftime('%Y-%m-%d %H:%M:%S', gmtime())}] {Fore.MAGENTA}FHR {format_hashrate(final_hash_rate)}{Style.RESET_ALL}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PythonCoin (PyC) Miner")
    parser.add_argument("-a", "--address", required=True, help="Wallet address")
    parser.add_argument("-w", "--worker", default="default_worker", help="Worker (rig) name")
    parser.add_argument("-u", "--serverurl", default="http://localhost:5000", help="Mining server URL")

    args = parser.parse_args()
    
    while True:
        mine_block(args.address, args.worker, args.serverurl)
