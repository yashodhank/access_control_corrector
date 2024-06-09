#!/usr/bin/env python3

import os
import re
import hashlib
import shutil
import logging
from logging.handlers import RotatingFileHandler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configurations
LOG_FILE = '/var/log/access_control_corrector.log'
MAX_LOG_SIZE = 50 * 1024 * 1024  # 50MB
APACHE_VHOSTS_PATH = '/etc/apache2/plesk.conf.d/vhosts/'

# Set up logging
logger = logging.getLogger('AccessControlCorrector')
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

file_hashes = {}
modification_stats = {}

def compute_file_hash(filepath):
    hash_md5 = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(4096):
                hash_md5.update(chunk)
    except Exception as e:
        logger.error(f'Error reading file for hash computation {filepath}: {e}')
        raise
    return hash_md5.hexdigest()

def is_acl_location_block(lines):
    acl_identifiers = [
        'Order Deny,Allow',
        'Deny from all',
        'Allow from'
    ]
    return all(identifier in lines for identifier in acl_identifiers)

def contains_ip_addresses(lines):
    ip_pattern = re.compile(r'\b\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?\b|\b[0-9a-fA-F:]+(\/\d{1,3})?\b')
    return any(ip_pattern.search(line) for line in lines)

def convert_to_modern_syntax(lines, indentation):
    new_lines = []
    for line in lines:
        stripped_line = line.strip()
        if 'Order Deny,Allow' in stripped_line:
            continue
        if 'Deny from all' in stripped_line:
            new_lines.append(f'{indentation}Require all denied\n')
        elif 'Allow from' in stripped_line:
            ips = re.findall(r'"([^"]+)"', stripped_line)
            for ip in ips:
                new_lines.append(f'{indentation}Require ip {ip}\n')
        else:
            new_lines.append(line)
    return new_lines

def correct_syntax(config_path):
    logger.debug(f'Correcting syntax for config_path: {config_path}')

    try:
        current_hash = compute_file_hash(config_path)
    except Exception as e:
        logger.error(f'Error computing file hash for {config_path}: {e}')
        return

    if file_hashes.get(config_path) == current_hash:
        logger.debug(f'No changes detected in {config_path}. Skipping.')
        return

    try:
        with open(config_path, 'r') as file:
            lines = file.readlines()
            logger.debug(f'Read {len(lines)} lines from {config_path}')
    except Exception as e:
        logger.error(f'Error reading file {config_path}: {e}')
        return

    modified_lines = []
    inside_location_block = False
    location_block = []
    block_start = None
    modifications_count = 0
    modifications_details = []

    for i, line in enumerate(lines):
        stripped_line = line.strip()
        if '<Location />' in stripped_line:
            inside_location_block = True
            location_block.append(line)
            block_start = i
            indentation = re.match(r'\s*', line).group()
        elif '</Location>' in stripped_line and inside_location_block:
            location_block.append(line)
            inside_location_block = False

            if is_acl_location_block("".join(location_block)) and contains_ip_addresses(location_block):
                logger.debug(f'Original Location Block in {config_path}:\n{"".join(location_block)}')
                modified_block = convert_to_modern_syntax(location_block, indentation)
                modifications_count += 1
                modifications_details.append({
                    'start_line': block_start + 1,
                    'end_line': i + 1,
                    'start_content': location_block[0].strip(),
                    'end_content': location_block[-1].strip()
                })
                location_block = modified_block
                logger.debug(f'Modified Location Block in {config_path}:\n{"".join(location_block)}')

            modified_lines.extend(location_block)
            location_block = []
            block_start = None
        elif inside_location_block:
            location_block.append(line)
        else:
            modified_lines.append(line)

    if inside_location_block:
        logger.warning(f'Unclosed <Location /> block detected in {config_path}. Skipping.')
        return

    if modifications_count > 0:
        if modified_lines:
            backup_path = f"{config_path}.bak"
            try:
                temp_file_path = f"{config_path}.tmp"
                with open(temp_file_path, 'w') as tmp_file:
                    tmp_file.writelines(modified_lines)

                shutil.copyfile(config_path, backup_path)
                os.replace(temp_file_path, config_path)  # Atomic write

                logger.info(f'Syntax corrected in {config_path}')
                file_hashes[config_path] = compute_file_hash(config_path)
                modification_stats[config_path] = {
                    'modifications_count': modifications_count,
                    'details': modifications_details
                }
            except Exception as e:
                logger.error(f'Error writing corrected file {config_path}: {e}')
                if temp_file_path and os.path.exists(temp_file_path):
                    os.remove(temp_file_path)

def display_modification_stats():
    total_modifications = sum(stat['modifications_count'] for stat in modification_stats.values())
    logger.info(f'\n{"-"*40}\nTotal Modifications Performed: {total_modifications}\n{"-"*40}')
    for config_path, stats in modification_stats.items():
        logger.info(f'File: {config_path}')
        logger.info(f'Modifications: {stats["modifications_count"]}')
        for detail in stats['details']:
            logger.info(f'  Modified Block from Line {detail["start_line"]} ({detail["start_content"][:30]}) to Line {detail["end_line"]} ({detail["end_content"][:30]})')

class DomainConfigHandler(FileSystemEventHandler):
    def process(self, event):
        if event.is_directory:
            return

        config_path = event.src_path
        if not config_path.endswith('.conf'):
            return

        if not os.path.exists(config_path):
            return

        logger.info(f'Configuration file modification detected: {config_path}')
        correct_syntax(config_path)

    def on_modified(self, event):
        self.process(event)

def main():
    if not os.path.exists(APACHE_VHOSTS_PATH):
        logger.error(f'Path {APACHE_VHOSTS_PATH} does not exist. Exiting...')
        return

    handler = DomainConfigHandler()

    try:
        observer = Observer()
        observer.schedule(handler, APACHE_VHOSTS_PATH, recursive=True)
        observer.start()
        logger.info('Started observing changes in Apache vhosts configurations.')
    except OSError as e:
        logger.error(f'Failed to start observer: {e}')
        return

    # Perform initial syntax correction for all configuration files
    for root, _, files in os.walk(APACHE_VHOSTS_PATH):
        for file in files:
            if file.endswith('.conf'):
                config_path = os.path.join(root, file)
                correct_syntax(config_path)

    try:
        while True:
            # Keep the script running
            pass
    except KeyboardInterrupt:
        observer.stop()
        logger.info('Shutting down observer due to keyboard interrupt.')
    finally:
        observer.join()
        display_modification_stats()

if __name__ == '__main__':
    main()
