import os
import subprocess
import multiprocessing
import logging
import time
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from apscheduler.schedulers.background import BackgroundScheduler

# Configure logger and log file settings
LOG_FILE = "process_results.txt"
MAX_LOG_SIZE = 4  # Max number of log entries to store (for example)
log_entries = deque(maxlen=MAX_LOG_SIZE)

# Global log counter
global_log_counter = multiprocessing.Value('i', 0)

# Shared memory counters for tracking the number of processed items
counter1 = multiprocessing.Value('i', 0)
counter2 = multiprocessing.Value('i', 0)
counter3 = multiprocessing.Value('i', 0)

# Setup logger function
def setup_logger():
    logger = logging.getLogger("ResultLogger")
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(message)s')
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger

# Function to log results
def log_result(result):
    log_entries.append(result)
    with open(LOG_FILE, 'a') as f:
        f.write(result + '\n')

# Script function that will run an external Python script
def run_script(script_name, input_path, counter, logger):
    try:
        # Run the external Python script with input_path as an argument
        process = subprocess.Popen(
            ['python', script_name, input_path], 
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        
        # Capture the output and errors from the subprocess
        stdout, stderr = process.communicate()

        # Decode the result
        result = stdout.decode() if stdout else stderr.decode()

        # Check exit code and log if successful
        if process.returncode == 0:
            # If script executed successfully, increment counters
            counter.value += 1
            with global_log_counter.get_lock():
                global_log_counter.value += 1
        else:
            # If script failed, handle accordingly
            result = f"Error in {script_name}: {stderr.decode()}"
        
        # Log the result
        log_result(result)

        # Print the result to the console
        print(result)

        return result
    except Exception as e:
        error_message = f"Error running {script_name}: {e}"
        log_result(error_message)
        print(error_message)
        return error_message

# Specific script functions
def script1(input_path, counter, logger):
    return run_script('./ransomware.py', input_path, counter, logger)

def script2(input_path, counter, logger):
    return run_script('./malware.py', input_path, counter, logger)

def script3(input_path, counter, logger):
    return run_script('./bruteforce.py', input_path, counter, logger)

# Run scripts concurrently and log results
def run_scripts_concurrently(input_path, counter1, counter2, counter3, logger):
    process1 = multiprocessing.Process(target=script1, args=(input_path, counter1, logger))
    process2 = multiprocessing.Process(target=script2, args=(input_path, counter2, logger))
    process3 = multiprocessing.Process(target=script3, args=(input_path, counter3, logger))

    # Start each process
    process1.start()
    process2.start()
    process3.start()

    # Wait for all processes to finish
    process1.join()
    process2.join()
    process3.join()

    return "All scripts have been processed concurrently."

# Watchdog handler that triggers when a new file is downloaded
class FileDownloadHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_download_time = time.time()

    def on_created(self, event):
        if event.is_directory:
            return

        # Update the last download time when a new file is downloaded
        self.last_download_time = time.time()
        print(f"New file downloaded: {event.src_path}")
        logger = setup_logger()

        # Run the scripts with the event path
        result1 = run_script('./ransomware.py', event.src_path, counter1, logger)
        result2 = run_script('./malware.py', event.src_path, counter2, logger)
        result3 = run_script('./bruteforce.py', event.src_path, counter3, logger)

        # Stop processing based on script results
        if "Error" in result1 or "Error" in result2 or "Error" in result3:
            print(f"Blocked download due to error in script processing: {event.src_path}")
            os.remove(event.src_path)  # Delete the file (stop further processing)
            return

        # You can add more conditions to block certain files based on results here:
        if "Processed by Script 1" in result1 and "ransomware" in result1:
            print(f"Blocked file due to detected ransomware: {event.src_path}")
            os.remove(event.src_path)  # Remove file if it matches a risky condition
            return

        # If no issues, process normally
        run_scripts_concurrently(event.src_path, counter1, counter2, counter3, logger)

    def check_for_inactivity(self):
        # If no file was downloaded in the last 10 minutes, run with root path
        if time.time() - self.last_download_time > 600:  # 600 seconds = 10 minutes
            logger = setup_logger()
            root_path = "/" if os.name != 'nt' else "C:/"
            print(f"No new file downloaded for 10 minutes. Using root path: {root_path}")
            run_scripts_concurrently(root_path, counter1, counter2, counter3, logger)
            self.last_download_time = time.time()

# Function to start monitoring a specific directory
def start_file_monitor(directory_to_watch, file_handler):
    observer = Observer()
    observer.schedule(file_handler, path=directory_to_watch, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
            # Check for inactivity every second
            file_handler.check_for_inactivity()
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# APScheduler - Periodic tasks
def periodic_task():
    # This task will be executed every 30 minutes
    logger = setup_logger()
    root_path = "/" if os.name != 'nt' else "C:/"
    print(f"Running periodic task. Using root path: {root_path}")
    run_scripts_concurrently(root_path, counter1, counter2, counter3, logger)

if __name__ == "__main__":
    # Start periodic background task (every 30 minutes)
    


    scheduler = BackgroundScheduler()
    scheduler.start()
    scheduler.add_job(func=periodic_task, trigger="interval", minutes=30)

    # Start file download monitoring
    file_handler = FileDownloadHandler()
    directory_to_watch = 'C:/'  # Change this to your directory
    start_file_monitor(directory_to_watch, file_handler)

    # Main loop for monitoring the file system and running tasks
    print("Monitoring started... Press Ctrl+C to stop.")
    while True:
        time.sleep(1)
