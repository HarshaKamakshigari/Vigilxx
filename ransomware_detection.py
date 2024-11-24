import os
import psutil
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from threading import Thread


LOG_DIRECTORY = "C:\\Logs"
MAIN_LOG_FILE = os.path.join(LOG_DIRECTORY, "ransomware_detection.log")
SUSPICIOUS_LOG_FILE = os.path.join(LOG_DIRECTORY, "suspicious_files.log")


if not os.path.exists(LOG_DIRECTORY):
    os.makedirs(LOG_DIRECTORY)


logging.basicConfig(filename=MAIN_LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")


suspicious_logger = logging.getLogger("suspicious")
suspicious_logger.setLevel(logging.WARNING)
suspicious_handler = logging.FileHandler(SUSPICIOUS_LOG_FILE)
suspicious_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
suspicious_logger.addHandler(suspicious_handler)

class RansomwareDetector(FileSystemEventHandler):
    def __init__(self):
        self.suspicious_extensions = ['.locked', '.encrypted', '.enc', '.crypto']
        self.checked_files = set()
        self.suspicious_processes = ["encrypt", "ransom"]
        self.file_modification_threshold = 10 
        self.time_window = 10  
        self.recent_file_modifications = []  

    def on_modified(self, event):
        if event.is_directory:
            return
        filename = event.src_path
        logging.info(f"File modified: {filename}")
        self.track_file_modifications(filename)
        if any(filename.endswith(ext) for ext in self.suspicious_extensions):
            suspicious_logger.warning(f"Suspicious file detected (modified): {filename}")
            self.checked_files.add(filename)

    def on_created(self, event):
        if event.is_directory:
            return
        filename = event.src_path
        logging.info(f"New file created: {filename}")
        if any(filename.endswith(ext) for ext in self.suspicious_extensions):
            suspicious_logger.warning(f"Suspicious file detected (created): {filename}")
            self.checked_files.add(filename)

    def track_file_modifications(self, filename):
  
        current_time = time.time()
        self.recent_file_modifications.append(current_time)

       
        self.recent_file_modifications = [
            ts for ts in self.recent_file_modifications if current_time - ts <= self.time_window
        ]

        if len(self.recent_file_modifications) > self.file_modification_threshold:
            suspicious_logger.warning(f"Mass file modification detected: {filename} and others.")
            logging.warning("Potential ransomware behavior detected: mass file modifications.")

    def kill_suspicious_processes(self):
       
        for proc in psutil.process_iter(attrs=['pid', 'name']):
            try:
                process_name = proc.info['name'].lower()
                if any(susp_proc in process_name for susp_proc in self.suspicious_processes):
                    logging.warning(f"Terminating suspicious process: {process_name} (PID: {proc.info['pid']})")
                    proc.terminate()
            except psutil.NoSuchProcess:
                pass

def monitor_system():
   
    paths_to_monitor = ["C:\\Users\\siras\\OneDrive\\Desktop"]  

    event_handler = RansomwareDetector()
    observer = Observer()

    for path in paths_to_monitor:
        if os.path.exists(path):
            observer.schedule(event_handler, path, recursive=True)
            logging.info(f"Monitoring folder: {path}")
        else:
            logging.warning(f"Path {path} does not exist and will not be monitored.")

    observer.start()
    logging.info("Monitoring system for ransomware-like behavior...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping ransomware detector...")
        observer.stop()
    observer.join()

def monitor_processes():
    detector = RansomwareDetector()
    while True:
        detector.kill_suspicious_processes()
        time.sleep(5)

if __name__ == "__main__":
    logging.info("Starting Ransomware Detection System (Behavioral Pattern)...")
    Thread(target=monitor_processes, daemon=True).start()
    monitor_system()
