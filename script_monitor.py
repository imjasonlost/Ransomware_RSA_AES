from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os
import subprocess
import logging

# Set up logging to capture file access patterns
logging.basicConfig(filename="ransomware_log.txt", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Track encryption status to allow the first attempt
encryption_detected_once = False

class RansomwareMonitor(FileSystemEventHandler):
    def on_created(self, event):
        global encryption_detected_once
        # Monitor for .enc files (encrypted files) and aes_key.bin creation
        if event.src_path.endswith('.enc') or 'aes_key.bin' in event.src_path:
            if not encryption_detected_once:
                # First detection: Log and alert the user but allow encryption
                logging.warning(f"First detection of encryption activity: {event.src_path}")
                print("Warning: Encryption activity detected. Files are being encrypted!")
                encryption_detected_once = True
            else:
                # Second detection: Actively stop the encryption
                logging.warning(f"Second detection of encryption activity: {event.src_path}. Stopping encryption.")
                print("Alert: Repeated encryption activity detected! Stopping the process.")
                self.terminate_ransomware()

    def on_deleted(self, event):
        # Log deletion of files, which could indicate removal of original files post-encryption
        logging.info(f"File deleted: {event.src_path} at {time.ctime()}")

    def terminate_ransomware(self):
        # Terminate the encryption process by stopping encrypt.py
        try:
            subprocess.run(["pkill", "-f", "encrypt.py"])
            logging.info("Encryption process terminated successfully.")
        except Exception as e:
            logging.error(f"Failed to terminate ransomware: {e}")

# Main function to set up monitoring
def main():
    path_to_watch = "C:\\Users\\ts1506\\Desktop\\Security"  # Adjust to the directory you are monitoring
    event_handler = RansomwareMonitor()
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()

    print("Watchdog is now monitoring directory:", path_to_watch)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()