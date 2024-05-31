#!/usr/bin/env python3

import os
import re
import subprocess
import time
import logging
import logging.handlers
from concurrent.futures import ThreadPoolExecutor, as_completed
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import ipaddress
import argparse

# Constants
APACHE_CONF_DIR = '/etc/apache2/sites-available'
DOMAIN_CONF_DIR = '/var/www/vhosts/system'
APACHE_SYNTAX = """<Location {location_path}>
    Order Deny,Allow
    Deny from all
    Allow from {ip_addresses}
</Location>"""

LSWS_SYNTAX = """<Location {location_path}>
    <RequireAll>
        Require all denied
        {require_ip}
    </RequireAll>
</Location>"""

# Set up logging with rotation
log_handler = logging.handlers.RotatingFileHandler(
    '/var/log/ip_syntax_switcher.log', maxBytes=10*1024*1024, backupCount=5)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.basicConfig(level=logging.INFO, handlers=[log_handler])
logger = logging.getLogger(__name__)

# Argument parser setup
parser = argparse.ArgumentParser(description="Apache LiteSpeed IP Allow/Deny Syntax Switcher for Plesk Panel")
parser.add_argument('--dry-run', action='store_true', help="Run in dry mode without making changes")
parser.add_argument('--debug', action='store_true', help="Run in debug mode")
args = parser.parse_args()

if args.debug:
    logger.setLevel(logging.DEBUG)

# Function to get active domains from Plesk
def get_active_domains():
    try:
        result = subprocess.run(['plesk', 'bin', 'domain', '--list'], capture_output=True, text=True, check=True)
        domains = result.stdout.split()
        logger.info(f"Active domains: {domains}")
        return domains
    except subprocess.CalledProcessError as e:
        logger.error(f"Error getting active domains: {e.stderr}")
        return []

# Function to check if LiteSpeed is the primary server
def is_litespeed_primary():
    try:
        result = subprocess.run(['systemctl', 'is-active', 'lsws'], capture_output=True, text=True)
        is_active = result.returncode == 0
        logger.info(f"LiteSpeed primary: {is_active}")
        return is_active
    except Exception as e:
        logger.error(f"Error checking LiteSpeed status: {str(e)}")
        return False

# Function to read and validate IP addresses from the Apache configuration file
def read_ip_addresses(content):
    matches = re.findall(r'Allow from ([\d\.\:\/\" ]+)', content)
    if matches:
        raw_ips = matches[0].replace('"', '').split()
        ip_addresses = [ip for ip in raw_ips if validate_ip_address(ip)]
        return ip_addresses
    return []

# Function to validate IP addresses and CIDR notation
def validate_ip_address(ip):
    try:
        ipaddress.ip_network(ip, strict=False)
        logger.debug(f"Validated IP address: {ip}")
        return True
    except ValueError:
        logger.warning(f"Invalid IP address: {ip}")
        return False

# Function to generate the appropriate configuration syntax
def generate_config(ip_addresses, litespeed, location_path):
    if litespeed:
        require_ip = "\n        ".join([f"Require ip {ip}" for ip in ip_addresses])
        config = LSWS_SYNTAX.format(location_path=location_path, require_ip=require_ip)
    else:
        allow_ip = " ".join([f'"{ip}"' for ip in ip_addresses])
        config = APACHE_SYNTAX.format(location_path=location_path, ip_addresses=allow_ip)
    return config

# Function to validate configuration
def validate_config(config_path):
    try:
        result = subprocess.run(['apachectl', 'configtest'], capture_output=True, text=True)
        if result.returncode == 0 and "Syntax OK" in result.stdout:
            logger.info(f"Config validation succeeded: {config_path}")
            return True
        else:
            logger.error(f"Config validation failed: {result.stdout.strip()} {result.stderr.strip()}")
            return False
    except subprocess.CalledProcessError as e:
        logger.error(f"Error validating config: {e.stderr}")
        return False

# Function to update configuration files for each domain
def update_domain_config(domain):
    conf_file = os.path.join(DOMAIN_CONF_DIR, domain, 'conf', 'httpd.conf')
    if not os.path.exists(conf_file):
        logger.warning(f"Config file not found for domain {domain}")
        return
    
    try:
        with open(conf_file, 'r') as file:
            content = file.read()
        
        ip_addresses = read_ip_addresses(content)
        if not ip_addresses:
            logger.info(f"No valid IP addresses found for {domain}")
            return
        
        litespeed = is_litespeed_primary()
        
        # Extract and update <Location> blocks
        location_blocks = re.findall(r'(<Location [^>]+>.*?</Location>)', content, re.DOTALL)
        for location_block in location_blocks:
            location_path_match = re.search(r'<Location ([^>]+)>', location_block)
            if location_path_match:
                location_path = location_path_match.group(1)
                updated_config = generate_config(ip_addresses, litespeed, location_path)
                content = content.replace(location_block, updated_config)

        config_path = os.path.join(APACHE_CONF_DIR, f"{domain}.conf")
        backup_path = f"{config_path}.bak"

        # Create a backup of the existing configuration file
        if os.path.exists(config_path):
            os.rename(config_path, backup_path)
            logger.info(f"Backup created for {domain}: {backup_path}")

        if args.dry_run:
            logger.info(f"Dry run: {config_path} would be updated with new IP configuration.")
        else:
            with open(config_path, 'w') as f:
                f.write(content)
            logger.info(f"Config file written for {domain}: {config_path}")

            if validate_config(config_path):
                if litespeed:
                    subprocess.run(['systemctl', 'reload', 'lsws'])
                else:
                    subprocess.run(['systemctl', 'reload', 'apache2'])
                logger.info(f"Config updated and validated for {domain}")
            else:
                # Restore the backup if validation fails
                if os.path.exists(backup_path):
                    os.rename(backup_path, config_path)
                logger.error(f"Config validation failed for {domain}, restored backup")
    except Exception as e:
        # Restore the backup if an error occurs
        if os.path.exists(backup_path):
            os.rename(backup_path, config_path)
        logger.error(f"Error updating config for {domain}: {str(e)}")
    finally:
        # Clean up the backup file if everything was successful
        if not args.dry_run and os.path.exists(backup_path):
            os.remove(backup_path)
            logger.info(f"Backup cleaned up for {domain}: {backup_path}")

# Function to monitor changes in domain configuration files
class ConfigChangeHandler(FileSystemEventHandler):
    def __init__(self, domains):
        self.domains = domains

    def on_modified(self, event):
        for domain in self.domains:
            if domain in event.src_path:
                logger.info(f"Detected change in {event.src_path}")
                update_domain_config(domain)
                break

# Function to update configurations for all domains
def update_configs(domains):
    with ThreadPoolExecutor(max_workers=min(os.cpu_count(), len(domains))) as executor:
        futures = {executor.submit(update_domain_config, domain): domain for domain in domains}
        for future in as_completed(futures):
            domain = futures[future]
            try:
                future.result()
                logger.info(f"Config updated for {domain}")
            except Exception as e:
                logger.error(f"Error updating config for {domain}: {str(e)}")

# Main function
def main():
    domains = get_active_domains()
    if not domains:
        logger.error("No active domains found. Exiting.")
        return
    
    update_configs(domains)

    event_handler = ConfigChangeHandler(domains)
    observer = Observer()
    for domain in domains:
        domain_conf_dir = os.path.join(DOMAIN_CONF_DIR, domain, 'conf')
        observer.schedule(event_handler, path=domain_conf_dir, recursive=True)
    
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
