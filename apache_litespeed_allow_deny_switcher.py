import os
import re
import time
import platform
import logging
import shutil
import argparse
import yaml
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Load configuration
def load_config(config_file='config.yaml'):
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

config = load_config()

# Constants from config
LOG_FILE = config['log_file']
LOG_MAX_SIZE = config['log_max_size']
BACKUP_EXT = config['backup_ext']
MAX_WORKERS = config['max_workers']
CHECK_INTERVAL = config['check_interval']
PATHS = config['paths']

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
    parser.add_argument('-l', '--log-max-size', type=int, help='Max log file size in bytes')
    parser.add_argument('-c', '--config', type=str, default='config.yaml', help='Path to configuration file')
    return parser.parse_args()

def validate_config(config):
    required_keys = ['log_file', 'log_max_size', 'backup_ext', 'max_workers', 'check_interval', 'paths']
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required configuration key: {key}")

def determine_active_mode():
    logger.info("Determining active web server mode...")
    if platform.system() == 'Linux':
        for path in PATHS['apache2']:
            if os.path.exists(path):
                logger.info(f"Active mode detected: Apache2 (path: {path})")
                return 'apache2', path
        for path in PATHS['litespeed']:
            if os.path.exists(path):
                logger.info(f"Active mode detected: LiteSpeed (path: {path})")
                return 'litespeed', path
    elif platform.system() == 'Windows':
        apache_path = PATHS['windows']['apache2']
        litespeed_path = PATHS['windows']['litespeed']
        if os.path.exists(apache_path):
            logger.info(f"Active mode detected: Apache2 (path: {apache_path})")
            return 'apache2', apache_path
        elif os.path.exists(litespeed_path):
            logger.info(f"Active mode detected: LiteSpeed (path: {litespeed_path})")
            return 'litespeed', litespeed_path
    raise RuntimeError('Unsupported OS or web server not installed.')

def load_conf_files(conf_dir):
    logger.info(f"Loading configuration files from directory: {conf_dir}")
    conf_files = {}
    for root, _, files in os.walk(conf_dir):
        for file in files:
            if file.endswith('.conf'):
                conf_path = os.path.join(root, file)
                with open(conf_path, 'r') as f:
                    conf_files[conf_path] = f.read()
                logger.debug(f"Loaded configuration file: {conf_path}")
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
    logger.debug(f"Original LiteSpeed <Location> block: {location_block}")

    location_block = location_block.replace('order allow,deny', 'Require all granted')
    location_block = location_block.replace('Order allow,deny', 'Require all granted')
    location_block = location_block.replace('deny from all', 'Require all denied')
    location_block = location_block.replace('Deny from all', 'Require all denied')
    location_block = re.sub(r'Allow from all', 'Require all granted', location_block)
    location_block = re.sub(r'Allow from\s+([^\s"]+)', r'Require ip \1', location_block)
    location_block = re.sub(r'Deny from\s+([^\s"]+)', r'Require not ip \1', location_block)

    logger.debug(f"Converted Apache2 <Location> block: {location_block}")
    return location_block

def convert_to_litespeed(match):
    location_block = match.group(0)
    logger.debug(f"Original Apache2 <Location> block: {location_block}")

    location_block = location_block.replace('Require all granted', 'Order allow,deny\nAllow from all')
    location_block = location_block.replace('Require all denied', 'Order allow,deny\nDeny from all')
    location_block = re.sub(r'Require ip\s+([^\s"]+)', r'Allow from \1', location_block)
    location_block = re.sub(r'Require not ip\s+([^\s"]+)', r'Deny from \1', location_block)

    logger.debug(f"Converted LiteSpeed <Location> block: {location_block}")
    return location_block

def update_conf_file(file_path, content, mode, dry_run):
    logger.info(f"Updating configuration file: {file_path}")
    if mode == 'apache2':
        updated_content = update_apache2_conf(content)
    else:
        updated_content = update_litespeed_conf(content)

    if content != updated_content:
        if not dry_run:
            backup_file(file_path)
            with open(file_path, 'w') as f:
                f.write(updated_content)
        logger.info(f"Configuration updated for: {file_path}")

def process_conf_files(conf_files, mode, dry_run):
    logger.info(f"Processing configuration files with mode: {mode}")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(update_conf_file, file_path, content, mode, dry_run) for file_path, content in conf_files.items()]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error processing file: {e}")
                logger.error(traceback.format_exc())

class ConfigFileHandler(FileSystemEventHandler):
    def __init__(self, conf_dir, mode, dry_run):
        self.conf_dir = conf_dir
        self.mode = mode
        self.dry_run = dry_run

    def on_modified(self, event):
        if event.src_path.endswith('.conf'):
            logger.info(f"Detected change in configuration file: {event.src_path}")
            try:
                conf_files = load_conf_files(self.conf_dir)
                process_conf_files(conf_files, self.mode, self.dry_run)
            except Exception as e:
                logger.error(f"Error handling modified file: {e}")
                logger.error(traceback.format_exc())

def monitor_and_update(dry_run):
    try:
        mode, conf_dir = determine_active_mode()
        event_handler = ConfigFileHandler(conf_dir, mode, dry_run)
        observer = Observer()
        observer.schedule(event_handler, path=conf_dir, recursive=True)
        observer.start()
        logger.info("File system observer started.")
    except Exception as e:
        logger.error(f"Failed to start monitoring: {e}")
        logger.error(traceback.format_exc())
        return

    try:
        while True:
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("Monitoring stopped by user.")
    except Exception as e:
        logger.error(f"Error during monitoring: {e}")
        logger.error(traceback.format_exc())
    finally:
        observer.join()

def main():
    args = parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if args.log_max_size:
        global LOG_MAX_SIZE
        LOG_MAX_SIZE = args.log_max_size
        handler.maxBytes = LOG_MAX_SIZE

    global config
    config = load_config(args.config)
    validate_config(config)

    logger.info("Web server configuration switch daemon started.")
    monitor_and_update(args.dry_run)

if __name__ == "__main__":
    main()
