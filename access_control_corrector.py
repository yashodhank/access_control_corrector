#!/usr/bin/env python3

import os
import subprocess
import logging
from logging.handlers import RotatingFileHandler
import time
import hashlib
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict
import asyncio
import aiofiles
import aiomultiprocess
import re
import shutil

# Configurations
LOG_FILE = '/var/log/access_control_corrector.log'
MAX_LOG_SIZE = 50 * 1024 * 1024  # 50MB
LOG_RETENTION = 3 * 30 * 24 * 60 * 60  # 3 months in seconds
CHECK_INTERVAL = 3600  # Check every hour
BATCH_INTERVAL = 10  # Batch interval for processing changes

# Set up argument parser
parser = argparse.ArgumentParser(description="Access Control Corrector Service")
parser.add_argument('--dry-run', action='store_true', help="Run in dry mode (no changes will be made)")
parser.add_argument('--verbose', action='store_true', help="Run in verbose mode (detailed logging)")
args = parser.parse_args()

# Set up logging
logger = logging.getLogger('AccessControlCorrector')
logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

domain_cache = {}
file_hashes = {}
last_web_server = None

def cleanup_old_logs():
    current_time = time.time()
    for root, _, files in os.walk('/var/log'):
        for file in files:
            file_path = os.path.join(root, file)
            if file_path.startswith(LOG_FILE) and os.path.getmtime(file_path) < (current_time - LOG_RETENTION):
                os.remove(file_path)
                logger.info(f'Removed old log file: {file_path}')

def is_web_server_running():
    try:
        netstat_output = subprocess.check_output(['netstat', '-ntlp'], text=True)
        ps_output = subprocess.check_output(['ps', 'aux'], text=True)
        
        apache_listening = re.search(r':80.*apache2|:443.*apache2', netstat_output)
        litespeed_listening = re.search(r':80.*litespeed|:443.*litespeed', netstat_output)

        if apache_listening and re.search(r'\bapache2\b', ps_output):
            return 'Apache2'
        elif litespeed_listening and re.search(r'\blitespeed\b', ps_output):
            return 'LiteSpeed'
    except subprocess.CalledProcessError as e:
        logger.error(f'Error checking web server status: {e}')
        return None

def detect_web_server():
    web_server = is_web_server_running()
    if web_server:
        return web_server
    return None

def domain_exists(domain):
    if domain in domain_cache:
        return domain_cache[domain]
    logger.debug(f'Checking if domain exists: {domain}')
    result = subprocess.run(['plesk', 'bin', 'domain', '-i', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    exists = result.returncode == 0
    domain_cache[domain] = exists
    if exists:
        logger.debug(f'Domain exists: {domain}')
    else:
        logger.debug(f'Domain does not exist: {domain}')
    return exists

def compute_file_hash(filepath):
    hash_md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

async def correct_syntax(domain, config_path, web_server):
    logger.debug(f'Correcting syntax for domain: {domain}, config_path: {config_path}, web_server: {web_server}')
    
    current_hash = compute_file_hash(config_path)
    if file_hashes.get(config_path) == current_hash:
        logger.debug(f'No changes detected in {config_path}. Skipping.')
        return
    
    async with aiofiles.open(config_path, 'r') as file:
        lines = await file.readlines()

    modified_lines = []
    for i, line in enumerate(lines):
        original_line = line
        if web_server == 'LiteSpeed':
            line = line.replace('Allow from', 'Allow').replace('Deny from', 'Deny')
        elif web_server == 'Apache2':
            line = line.replace('Allow', 'Allow from').replace('Deny', 'Deny from')
        if line != original_line:
            modified_lines.append((i + 1, original_line.strip(), line.strip()))

    if modified_lines:
        if not args.dry_run:
            backup_path = f"{config_path}.bak"
            shutil.copyfile(config_path, backup_path)
            async with aiofiles.open(config_path, 'w') as file:
                await file.writelines(lines)
            logger.info(f'Syntax corrected for {web_server} in {config_path} for domain: {domain}')
            file_hashes[config_path] = compute_file_hash(config_path)
        else:
            logger.info(f'[Dry-Run] Backup and syntax correction would be done for {config_path} (domain: {domain})')

        for line_no, original, modified in modified_lines:
            logger.debug(f"Line {line_no}: {original} -> {modified}")

def test_config(web_server):
    command = ['/usr/sbin/apache2ctl', 'configtest'] if web_server == 'Apache2' else ['/usr/local/lsws/bin/lswsctrl', 'restart']
    logger.debug(f'Testing configuration with command: {command}')
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.debug(f'Configuration test command output: {result.stdout.decode()}')
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f'Configuration test failed: {e.stderr.decode()}')
        return False

class DomainConfigHandler(FileSystemEventHandler):
    def __init__(self, web_server):
        self.web_server = web_server
        self.batch = defaultdict(set)
        self.loop = asyncio.get_event_loop()
        self.loop.create_task(self.process_batches())

    async def process_batches(self):
        while True:
            await asyncio.sleep(BATCH_INTERVAL)
            tasks = []
            async with aiomultiprocess.Pool() as pool:
                for domain, config_paths in self.batch.items():
                    for config_path in config_paths:
                        tasks.append(pool.apply(correct_syntax, args=(domain, config_path, self.web_server)))
            await asyncio.gather(*tasks)
            self.batch.clear()

    def schedule_processing(self, domain, config_path):
        self.batch[domain].add(config_path)
        logger.debug(f'Scheduled processing for domain: {domain}, config_path: {config_path}')

    def process(self, event):
        if event.is_directory:
            return

        config_path = event.src_path
        domain = os.path.basename(os.path.dirname(os.path.dirname(config_path)))
        if domain_exists(domain) and config_path.endswith('httpd.conf'):
            logger.info(f'Scheduling change in config for domain: {domain}')
            self.schedule_processing(domain, config_path)

    def on_modified(self, event):
        logger.debug(f'File modified: {event.src_path}')
        self.process(event)

    def on_created(self, event):
        logger.debug(f'File created: {event.src_path}')
        self.process(event)

def main():
    global last_web_server
    web_server = detect_web_server()

    if web_server != last_web_server:
        logger.info(f'Web server changed from {last_web_server} to {web_server}')
        last_web_server = web_server

    if web_server:
        observer = Observer()
        handler = DomainConfigHandler(web_server)
        observer.schedule(handler, path='/var/www/vhosts/system/', recursive=True)
        observer.start()
        try:
            while True:
                time.sleep(CHECK_INTERVAL)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
    else:
        logger.error('No web server detected. Exiting...')

if __name__ == "__main__":
    main()
