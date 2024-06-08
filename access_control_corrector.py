#!/usr/bin/env python3

import os
import subprocess
import logging
from logging.handlers import RotatingFileHandler
import time
import shutil
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict
import asyncio
import aiofiles
import aiomultiprocess

# Configurations
LOG_FILE = '/var/log/access_control_corrector.log'
MAX_LOG_SIZE = 50 * 1024 * 1024  # 50MB
LOG_RETENTION = 3 * 30 * 24 * 60 * 60  # 3 months in seconds
CHECK_INTERVAL = 3600  # Check every hour
VHOSTS_PATH = '/var/www/vhosts/system'  # Path for vhost configurations
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

domain_cache = {}

def cleanup_old_logs():
    current_time = time.time()
    for root, _, files in os.walk('/var/log'):
        for file in files:
            file_path = os.path.join(root, file)
            if file_path.startswith(LOG_FILE) and os.path.getmtime(file_path) < (current_time - LOG_RETENTION):
                os.remove(file_path)
                logger.info(f'Removed old log file: {file_path}')

def is_web_server_running(command):
    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def detect_web_server():
    apache_running = is_web_server_running(['/usr/sbin/apache2ctl', 'status'])
    litespeed_running = is_web_server_running(['/usr/local/lsws/bin/lswsctrl', 'status'])

    if apache_running and litespeed_running:
        logger.warning('Both Apache2 and LiteSpeed detected as running. Prioritizing Apache2.')
        return 'Apache2', 'LiteSpeed'
    elif apache_running:
        return 'Apache2', None
    elif litespeed_running:
        return 'LiteSpeed', None
    return None, None

def domain_exists(domain):
    if domain in domain_cache:
        return domain_cache[domain]
    result = subprocess.run(['/usr/local/psa/bin/domain', '-i', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    exists = result.returncode == 0
    domain_cache[domain] = exists
    return exists

async def correct_syntax(domain, config_path, web_server):
    async with aiofiles.open(config_path, 'r') as file:
        config = await file.readlines()

    if web_server == 'LiteSpeed':
        config = [line.replace('Allow from', 'Allow').replace('Deny from', 'Deny') for line in config]
    elif web_server == 'Apache2':
        config = [line.replace('Allow', 'Allow from').replace('Deny', 'Deny from') for line in config]

    backup_path = f"{config_path}.bak"
    if not args.dry_run:
        shutil.copyfile(config_path, backup_path)
        async with aiofiles.open(config_path, 'w') as file:
            await file.writelines(config)
        logger.info(f'Syntax corrected for {web_server} in {config_path} for domain: {domain}')
    else:
        logger.info(f'[Dry-Run] Backup and syntax correction would be done for {config_path} (domain: {domain})')

def test_config(web_server):
    command = ['/usr/sbin/apache2ctl', 'configtest'] if web_server == 'Apache2' else ['/usr/local/lsws/bin/lswsctrl', 'restart']
    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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

    def process(self, event):
        if event.is_directory:
            return

        config_path = event.src_path
        domain = os.path.basename(os.path.dirname(os.path.dirname(config_path)))
        if domain_exists(domain):
            logger.info(f'Scheduling change in config for domain: {domain}')
            self.schedule_processing(domain, config_path)

    def on_modified(self, event):
        self.process(event)

    def on_created(self, event):
        self.process(event)

def main():
    web_server, _ = detect_web_server()
    if web_server:
        logger.info(f'{web_server} detected as active web server.')

        event_handler = DomainConfigHandler(web_server)
        observer = Observer()
        observer.schedule(event_handler, path=VHOSTS_PATH, recursive=True)
        observer.start()

        try:
            while True:
                time.sleep(CHECK_INTERVAL)
                cleanup_old_logs()
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
    else:
        logger.warning('No web server detected.')

if __name__ == '__main__':
    main()
