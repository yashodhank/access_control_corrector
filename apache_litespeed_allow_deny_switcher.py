import os
import re
import time
import platform
import logging
import shutil
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Constants
LOG_FILE = '/var/log/webserver_switch.log'
LOG_MAX_SIZE = 10 * 1024 * 1024  # 10 MB
BACKUP_EXT = '.bak'
MAX_WORKERS = 4  # Adjust based on system capabilities
CHECK_INTERVAL = 10  # Seconds

# Paths for Plesk-supported OSes
APACHE2_CONF_DIRS = [
    '/etc/apache2/sites-available/',  # Debian, Ubuntu
    '/etc/httpd/conf.d/'  # CentOS, RHEL, CloudLinux, AlmaLinux, Rocky Linux, Virtuozzo Linux
]
LITESPEED_CONF_DIRS = [
    '/usr/local/lsws/conf/vhosts/',  # Common location for LiteSpeed
]

# Setup logging
logger = logging.getLogger('WebServerSwitch')
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_SIZE, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def parse_args():
    parser = argparse.ArgumentParser(description='Daemon for switching between Apache2 and LiteSpeed configuration syntax.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    parser.add_argument('-d', '--dry-run', action='store_true', help='Enable dry run mode')
    parser.add_argument('-l', '--log-max-size', type=int, default=LOG_MAX_SIZE, help='Max log file size in bytes')
    return parser.parse_args()

def determine_active_mode():
    if platform.system() == 'Linux':
        for path in APACHE2_CONF_DIRS:
            if os.path.exists(path):
                return 'apache2', path
        for path in LITESPEED_CONF_DIRS:
            if os.path.exists(path):
                return 'litespeed', path
    elif platform.system() == 'Windows':
        apache_path = 'C:\\Apache24\\conf\\vhosts\\'
        litespeed_path = 'C:\\litespeed\\conf\\vhosts'
        if os.path.exists(apache_path):
            return 'apache2', apache_path
        elif os.path.exists(litespeed_path):
            return 'litespeed', litespeed_path
    raise RuntimeError('Unsupported OS or web server not installed.')

def load_conf_files(conf_dir):
    conf_files = {}
    for root, _, files in os.walk(conf_dir):
        for file in files:
            if file.endswith('.conf'):
                conf_path = os.path.join(root, file)
                with open(conf_path, 'r') as f:
                    conf_files[conf_path] = f.read()
    return conf_files

def backup_file(file_path):
    backup_path = file_path + BACKUP_EXT
    shutil.copyfile(file_path, backup_path)
    logger.info(f"Backup created: {backup_path}")

def update_apache2_conf(content):
    pattern = re.compile(r'<Location .*?>.*?</Location>', re.DOTALL)
    updated_content = re.sub(pattern, convert_to_apache2, content)
    return updated_content

def update_litespeed_conf(content):
    pattern = re.compile(r'<Location .*?>.*?</Location>', re.DOTALL)
    updated_content = re.sub(pattern, convert_to_litespeed, content)
    return updated_content

def convert_to_apache2(match):
    location_block = match.group(0)
    location_block = location_block.replace('order allow,deny', 'Require all granted')
    location_block = location_block.replace('deny from all', 'Require all denied')
    return location_block

def convert_to_litespeed(match):
    location_block = match.group(0)
    location_block = location_block.replace('Require all granted', 'order allow,deny')
    location_block = location_block.replace('Require all denied', 'deny from all')
    return location_block

def update_conf_file(file_path, content, mode, dry_run):
    if mode == 'apache2':
        updated_content = update_apache2_conf(content)
    else:
        updated_content = update_litespeed_conf(content)

    if content != updated_content:
        if not dry_run:
            backup_file(file_path)
            with open(file_path, 'w') as f:
                f.write(updated_content)
        logger.info(f"Updated configuration: {file_path}")

def process_conf_files(conf_files, mode, dry_run):
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(update_conf_file, file_path, content, mode, dry_run) for file_path, content in conf_files.items()]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error processing file: {e}")

class ConfigFileHandler(FileSystemEventHandler):
    def __init__(self, conf_dir, mode, dry_run):
        self.conf_dir = conf_dir
        self.mode = mode
        self.dry_run = dry_run

    def on_modified(self, event):
        if event.src_path.endswith('.conf'):
            logger.info(f"Detected change in configuration file: {event.src_path}")
            conf_files = load_conf_files(self.conf_dir)
            process_conf_files(conf_files, self.mode, self.dry_run)

def monitor_and_update(dry_run):
    mode, conf_dir = determine_active_mode()
    event_handler = ConfigFileHandler(conf_dir, mode, dry_run)
    observer = Observer()
    observer.schedule(event_handler, path=conf_dir, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def main():
    args = parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logger.info("Web server configuration switch daemon started.")
    monitor_and_update(args.dry_run)

if __name__ == "__main__":
    main()
