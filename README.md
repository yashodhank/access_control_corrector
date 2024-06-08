# Access Control Corrector for Plesk Panel - Apache2 & LiteSpeed Enterprise Web Server

The Access Control Corrector script is designed to ensure the correct syntax for access control directives in Apache2 and LiteSpeed web server configuration files on Plesk-supported Linux systems. The script operates autonomously, continuously monitoring configuration files for changes and correcting them as needed. 

## Features

- Detects and identifies the active web server (Apache2 or LiteSpeed).
- Monitors configuration files for all active and suspended domains and subdomains.
- Corrects access control directives syntax (`Allow`/`Deny` for Apache2 and LiteSpeed).
- Ensures changes do not break the web server by validating configurations before applying them.
- Maintains detailed logs with automated rotation and cleanup.
- Supports dry-run and verbose modes for testing and troubleshooting.
- Batch processing for efficient handling of multiple changes.
- Automated installation and updating scripts.

## Supported OS

This script is compatible with the following Plesk Panel Supported Linux OS:
- Debian 10, 11, 12
- Ubuntu 18.04, 20.04, 22.04, 24.04
- Ubuntu 22.04 LTS for ARM
- CentOS 7.x
- Red Hat Enterprise Linux 7.x, 8.x, 9.x
- CloudLinux 7.x, 8.x
- AlmaLinux 8.x, 9.x
- Rocky Linux 8.x
- Virtuozzo Linux 7

## Installation

### Automated Installation

To install the script, run the following command:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/yashodhank/access_control_corrector/main/install_access_control_corrector.sh || wget -qO- https://raw.githubusercontent.com/yashodhank/access_control_corrector/main/install_access_control_corrector.sh)"
```

This command will:
- Install necessary dependencies.
- Clone the repository.
- Set up a Python virtual environment.
- Install required Python packages.
- Create and start a systemd service to run the script.

### Manual Installation

1. **Download or Clone the Repository**:
   ```bash
   git clone https://github.com/yashodhank/access_control_corrector.git
   cd access_control_corrector
   ```

2. **Make Scripts Executable**:
   ```bash
   chmod +x install_access_control_corrector.sh
   chmod +x update_access_control_corrector.sh
   ```

3. **Run the Installer Script**:
   ```bash
   sudo ./install_access_control_corrector.sh
   ```

## Updating

To update the script, run the updater script:

```bash
sudo ./update_access_control_corrector.sh
```

## Usage

### Running in Dry-Run Mode

You can run the script in dry-run mode to see what changes would be made without actually applying them:

```bash
sudo systemctl stop access_control_corrector.service
source /opt/access_control_corrector/venv/bin/activate
python /opt/access_control_corrector/access_control_corrector.py --dry-run --verbose
```

### Verbose Mode

Verbose mode provides detailed logging for troubleshooting:

```bash
sudo systemctl stop access_control_corrector.service
source /opt/access_control_corrector/venv/bin/activate
python /opt/access_control_corrector/access_control_corrector.py --verbose
```

### Examples

- **Correcting Syntax**: The script detects changes in configuration files and corrects access control syntax for Apache2 and LiteSpeed.
- **Batch Processing**: If multiple configuration files are changed within a short period, the script processes them in batches to optimize performance.
- **Resilient Operation**: The script ensures that configuration changes do not break the web server by validating configurations before applying them. If a change fails, the script restores the previous working configuration.
- **Logging**: Detailed logs are maintained with automatic rotation and cleanup to prevent excessive disk usage.

## Systemd Service Management

- **Check Service Status**:
  ```bash
  sudo systemctl status access_control_corrector.service
  ```

- **Start Service**:
  ```bash
  sudo systemctl start access_control_corrector.service
  ```

- **Stop Service**:
  ```bash
  sudo systemctl stop access_control_corrector.service
  ```

- **Restart Service**:
  ```bash
  sudo systemctl restart access_control_corrector.service
  ```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.