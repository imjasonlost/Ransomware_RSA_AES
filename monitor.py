
#from multiprocessing import process
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
import time
import logging
import os

# Set up logging to capture activity
logging.basicConfig(filename="activity_log.txt", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DirectoryActivityHandler(FileSystemEventHandler):
   
  def on_created(self, event): 
        # Monitor for .enc files (encrypted files) and aes_key.bin creation
         if any(event.src_path.endswith(ext) for ext in ['.enc', '.locked', '.encrypted']) or 'aes_key.bin' in event.src_path:
         #if event.src_path.endswith('.enc'):
        
           self.kill_encrypt_process()
  def kill_encrypt_process(self):
        # Terminate the encryption process by stopping encrypt.py
        try:
           for process in psutil.process_iter(['pid', 'name', 'cmdline']):
            # Check if "encrypt.py" is part of the command line arguments
            cmdline = process.info.get('cmdline')
            if cmdline and "encrypt.py" in cmdline:
                process.terminate()  # Terminate the process
                logging.info(f"Terminated process: {process.info['pid']} - encrypt.py")
                print("Encryption process terminated successfully.")
        except Exception as e:
            logging.error(f"Failed to terminate ransomware: {e}")
            """"
  def on_created(self, event):
        if event.is_directory:
            return
        logging.info(f"File created: {event.src_path}")
        print(f"File created: {event.src_path}")

   def on_modified(self, event):
        if event.is_directory:
          return
        logging.info(f"File modified: {event.src_path}")
        print(f"File modified: {event.src_path}")

   def on_deleted(self, event):
        if event.is_directory:
           return
        logging.info(f"File deleted: {event.src_path}")
        print(f"File deleted: {event.src_path}")  
  
    """
def monitor_directory(path_to_watch):
    # Set up observer and handler for the directory
    event_handler = DirectoryActivityHandler()
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()
    print(f"Monitoring activities in directory: {path_to_watch}")

    try:
        while True:
            time.sleep(1)  # Keep the script running
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Example usage
if __name__ == "__main__":
    path_to_watch = "C:\\Jason\\Computer Security"  # Replace with the directory you want to monitor
    monitor_directory(path_to_watch)
