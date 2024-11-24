import os
import time
import re
import subprocess
import threading
from collections import defaultdict, deque
from datetime import datetime
import argparse
import logging
from logging.handlers import RotatingFileHandler

LOG_FILE = r"C:\Windows\System32\winevt\Logs\Security.evtx"
FAILED_LOG_FILE = r"C:\Users\siras\Documents\failed_logins.log"
BLOCKED_LOG_FILE = r"C:\Users\siras\Documents\blocked_ips.log"
THRESHOLD = 2  
TIME_WINDOW = 60  
POLL_INTERVAL = 5   

# Create directories if they don't exist
for log_path in [FAILED_LOG_FILE, BLOCKED_LOG_FILE]:
    log_dir = os.path.dirname(log_path)
    os.makedirs(log_dir, exist_ok=True)

# Set up logging with rotating handler
logger = logging.getLogger(__name__)
handler = RotatingFileHandler(FAILED_LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Initialize the dictionary to track failed attempts
failed_attempts = defaultdict(lambda: deque(maxlen=THRESHOLD))
failed_attempts_lock = threading.Lock()

def block_ip(ip):
    try:
        logger.info(f"Blocking IP: {ip}")
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=BlockBruteForce",
                        "dir=in", "action=block", "remoteip=" + ip], check=True)
        
        with open(BLOCKED_LOG_FILE, "a") as blocked_file:
            blocked_file.write(f"{datetime.now()} - Blocked IP: {ip}\n")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to block IP {ip}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error blocking IP {ip}: {e}")

def log_failed_attempt(ip, timestamp):
    logger.info(f"Failed login attempt from IP: {ip} at {datetime.fromtimestamp(timestamp)}")
    with open(FAILED_LOG_FILE, "a") as failed_file:
        failed_file.write(f"{datetime.fromtimestamp(timestamp)} - Failed login attempt from IP: {ip}\n")

def monitor_logs():
    global failed_attempts
    last_query_time = time.time()

    while True:
        try:
            command = f'wevtutil qe Security "/q:*[System[Provider[@Name=\'Microsoft-Windows-Security-Auditing\'] and (EventID=4625)]]" /f:text /c:10 /rd:true'
            result = subprocess.run(command, capture_output=True, text=True, shell=True)

            if result.returncode == 0:
                log_data = result.stdout
                matches = re.findall(r"Source Network Address\s*:\s*(\d+\.\d+\.\d+\.\d+)", log_data)

                if matches:
                    for ip in matches:
                        timestamp = time.time()
                        with failed_attempts_lock:
                            failed_attempts[ip].append(timestamp)

                        log_failed_attempt(ip, timestamp)

                        if len(failed_attempts[ip]) >= THRESHOLD:
                            block_ip(ip)

            time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            logger.info("Stopping log monitoring.")
            break
        except Exception as e:
            logger.error(f"Error monitoring logs: {e}")

def monitor_blocked_ips():
    while True:
        time.sleep(POLL_INTERVAL)
        logger.info(f"Currently blocked IPs: {list(failed_attempts.keys())}")

def start_monitoring():
    log_thread = threading.Thread(target=monitor_logs)
    log_thread.daemon = True
    log_thread.start()

    block_thread = threading.Thread(target=monitor_blocked_ips)
    block_thread.daemon = True
    block_thread.start()

    log_thread.join()
    block_thread.join()

def parse_args():
    parser = argparse.ArgumentParser(description="Brute Force Monitor and Response")
    parser.add_argument("--log-file", default=LOG_FILE, help="Path to the Windows event log file (default: Security.evtx)")
    parser.add_argument("--failed-log-file", default=FAILED_LOG_FILE, help="Path to log failed login attempts")
    parser.add_argument("--blocked-log-file", default=BLOCKED_LOG_FILE, help="Path to log blocked IPs")
    parser.add_argument("--threshold", type=int, default=THRESHOLD, help="Threshold for failed login attempts to trigger block")
    parser.add_argument("--time-window", type=int, default=TIME_WINDOW, help="Time window in seconds to track failed attempts")
    parser.add_argument("--poll-interval", type=int, default=POLL_INTERVAL, help="Polling interval for logs in seconds")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    LOG_FILE = args.log_file
    FAILED_LOG_FILE = args.failed_log_file
    BLOCKED_LOG_FILE = args.blocked_log_file
    THRESHOLD = args.threshold
    TIME_WINDOW = args.time_window
    POLL_INTERVAL = args.poll_interval

    print("Starting brute-force monitoring...")
    start_monitoring()
