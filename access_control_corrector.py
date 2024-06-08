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
import requests
import tempfile

# Configurations
LOG_FILE = '/var/log/access_control_corrector.log'
MAX_LOG_SIZE = 50 * 1024 * 1024  # 50MB
LOG_RETENTION = 3 * 30 * 24 * 60 * 60  # 3 months in seconds
CHECK_INTERVAL = 3600  # Check every hour
BATCH_INTERVAL = 10  # Batch interval for processing changes
APACHE_VHOSTS_PATH = '/etc/apache2/plesk.conf.d/vhosts/'

# Set up argument parser
parser = argparse.ArgumentParser(description="Access Control Corrector Service")
parser.add_argument('--dry-run', action='store_true', help="Run in dry mode (no changes will be made)")
parser.add_argument('--verbose', choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL', 'PANIC'], default='ERROR', help="Set the logging level")
args = parser.parse_args()

# Set up logging
logger = logging.getLogger('AccessControlCorrector')
logger.setLevel(getattr(logging, args.verbose))
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

def update_domain_cache():
    domains = get_plesk_domains()
    domain_cache.update({domain: True for domain in domains})

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

def get_plesk_domains():
    logger.info('Fetching list of domains from Plesk...')
    try:
        result = subprocess.run(['plesk', 'bin', 'domain', '--list'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        domains = result.stdout.splitlines()
        domain_cache.update({domain: True for domain in domains})
        logger.debug(f'Domains found: {domains}')
        return domains
    except subprocess.CalledProcessError as e:
        logger.error(f'Error fetching domains from Plesk: {e.stderr}')
        return []

def domain_exists(domain):
    if domain not in domain_cache:
        update_domain_cache()
    return domain_cache.get(domain, False)

async def compute_file_hash(filepath):
    hash_md5 = hashlib.md5()
    try:
        async with aiofiles.open(filepath, 'rb') as f:
            while True:
                chunk = await f.read(4096)
                if not chunk:
                    break
                hash_md5.update(chunk)
    except Exception as e:
        logger.error(f'Error reading file for hash computation {filepath}: {e}')
        raise
    return hash_md5.hexdigest()

def contains_ip_address(line):
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b')
    return bool(ip_pattern.search(line))

async def correct_syntax(domain, config_path, web_server):
    logger.debug(f'Correcting syntax for domain: {domain}, config_path: {config_path}, web_server: {web_server}')
    
    try:
        current_hash = await compute_file_hash(config_path)
    except Exception as e:
        logger.error(f'Error computing file hash for {config_path}: {e}')
        return

    if file_hashes.get(config_path) == current_hash:
        logger.debug(f'No changes detected in {config_path}. Skipping.')
        return
    
    try:
        async with aiofiles.open(config_path, 'r') as file:
            lines = await file.readlines()
    except Exception as e:
        logger.error(f'Error reading file {config_path}: {e}')
        return

    modified_lines = []
    allow_pattern = re.compile(r'\bAllow from\b', re.IGNORECASE)
    deny_pattern = re.compile(r'\bDeny from\b', re.IGNORECASE)
    order_pattern = re.compile(r'\bOrder\b', re.IGNORECASE)
    
    inside_acl_block = False
    acl_block_start = None

    for i, line in enumerate(lines):
        original_line = line
        if web_server == 'LiteSpeed':
            if contains_ip_address(line):
                inside_acl_block = True
                if acl_block_start is None:
                    acl_block_start = i
            elif inside_acl_block and not contains_ip_address(line):
                inside_acl_block = False
                acl_block_start = None

            if inside_acl_block:
                line = allow_pattern.sub('Allow', line)
                line = deny_pattern.sub('Deny', line)
                if order_pattern.search(line):
                    line = re.sub(r'Order Deny,Allow', 'Order Allow,Deny', line)
        elif web_server == 'Apache2':
            if contains_ip_address(line):
                inside_acl_block = True
                if acl_block_start is None:
                    acl_block_start = i
            elif inside_acl_block and not contains_ip_address(line):
                inside_acl_block = False
                acl_block_start = None

            if inside_acl_block:
                line = re.sub(r'\bAllow\b(?! from)', 'Allow from', line)
                line = re.sub(r'\bDeny\b(?! from)', 'Deny from', line)

        if line != original_line:
            lines[i] = line
            modified_lines.append((i + 1, original_line.strip(), line.strip()))

    if modified_lines:
        if not args.dry_run:
            backup_path = f"{config_path}.bak"
            try:
                temp_file_path = None
                async with aiofiles.open(config_path, 'r') as f:
                    temp_file_path = f"{config_path}.tmp"
                    async with aiofiles.open(temp_file_path, 'w') as tmp_file:
                        await tmp_file.writelines(lines)
                
                shutil.copyfile(config_path, backup_path)
                os.replace(temp_file_path, config_path)  # Atomic write
                
                logger.info(f'Syntax corrected for {web_server} in {config_path} for domain: {domain}')
                file_hashes[config_path] = await compute_file_hash(config_path)
            except Exception as e:
                logger.error(f'Error writing corrected file {config_path}: {e}')
                if temp_file_path and os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
        else:
            logger.info(f'[Dry-Run] Backup and syntax correction would be done for {config_path} (domain: {domain})')

        for line_no, original, modified in modified_lines:
            logger.debug(f"Line {line_no}: {original} -> {modified}")

def validate_config_file(config_path):
    if not os.path.exists(config_path):
        logger.error(f'Configuration file {config_path} does not exist.')
        return False
    if not os.access(config_path, os.R_OK | os.W_OK):
        logger.error(f'Configuration file {config_path} is not readable/writable.')
        return False
    return True

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

def check_403_error(domain):
    try:
        response = requests.get(f'http://{domain}')
        if response.status_code == 403:
            return True
    except requests.RequestException as e:
        logger.error(f'Error checking domain {domain} for 403 error: {e}')
    return False

async def initial_check(web_server):
    logger.info('Performing initial check on all domain configurations...')
    domains = get_plesk_domains()
    async with aiomultiprocess.Pool() as pool:
        tasks = [
            pool.apply(correct_syntax, args=(domain, os.path.join(APACHE_VHOSTS_PATH, f'{domain}.conf'), web_server))
            for domain in domains if os.path.exists(os.path.join(APACHE_VHOSTS_PATH, f'{domain}.conf'))
        ]
        await asyncio.gather(*tasks)


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
                        if check_403_error(domain):
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
        if not config_path.endswith('.conf'):
            return

        domain = os.path.splitext(os.path.basename(config_path))[0]
        if domain_exists(domain):
            logger.info(f'Scheduling change in config for domain: {domain}')
            self.schedule_processing(domain, config_path)

    def on_modified(self, event):
        logger.debug(f'File modified: {event.src_path}')
        self.process(event)

def main():
    global last_web_server
    web_server = detect_web_server()
    if not web_server:
        logger.error('No active web server detected. Exiting...')
        return
    logger.info(f'Web server changed from {last_web_server} to {web_server}')
    last_web_server = web_server

    # Ensure the observer path exists
    if not os.path.exists(APACHE_VHOSTS_PATH):
        logger.error(f'Path {APACHE_VHOSTS_PATH} does not exist. Exiting...')
        return

    handler = DomainConfigHandler(web_server)
    observer = Observer()
    try:
        observer.schedule(handler, path=APACHE_VHOSTS_PATH, recursive=True)
        observer.start()
    except OSError as e:
        logger.error(f'Failed to start observer: {e}')
        return

    try:
        asyncio.run(initial_check(web_server))
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        observer.stop()
    finally:
        observer.join()

if __name__ == '__main__':
    cleanup_old_logs()
    main()
