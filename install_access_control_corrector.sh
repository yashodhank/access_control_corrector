#!/bin/bash

# Configuration
SCRIPT_NAME="access_control_corrector.py"
INSTALL_DIR="/opt/access_control_corrector"
SERVICE_NAME="access_control_corrector.service"
SERVICE_FILE_PATH="/etc/systemd/system/$SERVICE_NAME"
VENV_DIR="$INSTALL_DIR/venv"
REPO_URL="https://github.com/yashodhank/access_control_corrector.git"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Detect OS and install dependencies
install_dependencies() {
    if [ -f /etc/debian_version ]; then
        apt-get update
        apt-get install -y python3 python3-venv git
    elif [ -f /etc/redhat-release ]; then
        yum install -y epel-release
        yum install -y python3 python3-venv git
    elif [ -f /etc/almalinux-release ] || [ -f /etc/rocky-release ] || [ -f /etc/centos-release ]; then
        dnf install -y epel-release
        dnf install -y python3 python3-venv git
    elif [ -f /etc/os-release ] && grep -q "Virtuozzo" /etc/os-release; then
        yum install -y epel-release
        yum install -y python3 python3-venv git
    else
        echo "Unsupported OS. Exiting."
        exit 1
    fi
}

# Install dependencies
install_dependencies

# Clone the repository
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
fi
git clone -q --progress --depth 1 "$REPO_URL" "$INSTALL_DIR"

# Set up Python virtual environment
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# Install Python packages
pip install --upgrade pip
pip install -r "$INSTALL_DIR/requirements.txt"

# Deactivate virtual environment
deactivate

# Create systemd service file
cat <<EOL > $SERVICE_FILE_PATH
[Unit]
Description=Access Control Corrector Service
After=network.target

[Service]
ExecStart=$VENV_DIR/bin/python $INSTALL_DIR/$SCRIPT_NAME --verbose
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd, enable and start the service
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

echo "Installation completed successfully."
