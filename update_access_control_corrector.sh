#!/bin/bash

# Configuration
SCRIPT_NAME="access_control_corrector.py"
INSTALL_DIR="/opt/access_control_corrector"
SERVICE_NAME="access_control_corrector.service"
REPO_URL="https://github.com/yashodhank/access_control_corrector.git"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Stop the service
systemctl stop $SERVICE_NAME

# Update the repository
cd "$INSTALL_DIR"
git pull origin main

# Activate virtual environment and install dependencies
source "$INSTALL_DIR/venv/bin/activate"
pip install --upgrade pip
pip install aiofiles aiomultiprocess watchdog
deactivate

# Start the service
systemctl start $SERVICE_NAME

echo "Update completed successfully."
