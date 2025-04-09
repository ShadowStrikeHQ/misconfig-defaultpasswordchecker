import argparse
import logging
import os
import re
import json
import yaml
import psutil
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define default credentials database (expand as needed)
DEFAULT_PASSWORDS = {
    "admin": "admin",
    "root": "root",
    "user": "password",
    "postgres": "postgres",
    "mysql": "mysql"
}

class DefaultPasswordChecker:
    """
    Scans configuration files and running processes for the presence of default passwords.
    """

    def __init__(self, root_dir="/", process_scan=True):
        """
        Initializes the DefaultPasswordChecker.

        Args:
            root_dir (str, optional): The root directory to start the file system scan. Defaults to "/".
            process_scan (bool, optional): Whether to scan running processes. Defaults to True.
        """
        self.root_dir = root_dir
        self.process_scan = process_scan
        self.findings = []  # List to store findings

    def scan_file(self, filepath):
        """
        Scans a file for default passwords.

        Args:
            filepath (str): The path to the file to scan.
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                self.check_content(content, filepath)
        except FileNotFoundError:
            logging.error(f"File not found: {filepath}")
        except Exception as e:
            logging.error(f"Error reading file {filepath}: {e}")

    def check_content(self, content, filepath):
        """
        Checks the content of a file for default passwords using regex.

        Args:
            content (str): The content of the file.
            filepath (str): The path to the file.
        """
        for username, password in DEFAULT_PASSWORDS.items():
            # Create regex patterns for both username and password, also hashing options
            patterns = [
                rf"(?i){username}\s*[:=]\s*['\"]?{password}['\"]?",
                rf"(?i){password}\s*[:=]\s*['\"]?{username}['\"]?",
                rf"(?i){hashlib.md5(password.encode()).hexdigest()}",  # Check MD5 hash
                rf"(?i){hashlib.sha256(password.encode()).hexdigest()}", #Check SHA256 hash
            ]

            for pattern in patterns:
              if re.search(pattern, content):
                self.findings.append({
                    "filepath": filepath,
                    "username": username,
                    "password": password,
                    "match_type": "regex",
                    "description": f"Default password '{password}' found for username '{username}' in {filepath}"
                })
                logging.warning(f"Possible default password found in {filepath} - Username: {username}, Password: {password}")
                break # Avoid redundant findings for the same file and credentials.

    def scan_directory(self):
        """
        Crawls the file system and scans files for default passwords.
        """
        for root, _, files in os.walk(self.root_dir):
            for file in files:
                filepath = os.path.join(root, file)
                self.scan_file(filepath)

    def scan_processes(self):
        """
        Scans running processes for default passwords in command-line arguments.
        """
        for process in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = process.info['cmdline']
                if cmdline:  # Check if cmdline is not None or empty
                    cmdline_str = ' '.join(cmdline)
                    for username, password in DEFAULT_PASSWORDS.items():
                        patterns = [
                            rf"(?i){username}\s*[:=]\s*['\"]?{password}['\"]?",
                            rf"(?i){password}\s*[:=]\s*['\"]?{username}['\"]?"
                        ]
                        for pattern in patterns:
                            if re.search(pattern, cmdline_str):
                                self.findings.append({
                                    "process_name": process.info['name'],
                                    "pid": process.info['pid'],
                                    "username": username,
                                    "password": password,
                                    "match_type": "process_cmdline",
                                    "description": f"Default password '{password}' found for username '{username}' in process '{process.info['name']}' (PID: {process.info['pid']})"
                                })
                                logging.warning(f"Possible default password found in process '{process.info['name']}' (PID: {process.info['pid']}) - Username: {username}, Password: {password}")
                                break # Avoid redundant findings for the same process credentials.

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                logging.warning(f"Error accessing process information for PID {process.info['pid']}: {e}")
            except Exception as e:
                logging.error(f"Unexpected error while scanning process {process.info['pid']}: {e}")

    def run_scan(self):
        """
        Runs the complete scan (directory and processes).
        """
        logging.info(f"Starting scan in directory: {self.root_dir}")
        self.scan_directory()

        if self.process_scan:
            logging.info("Scanning running processes...")
            self.scan_processes()

        if self.findings:
            logging.info("Scan completed.  Possible default passwords found.")
            return self.findings
        else:
            logging.info("Scan completed. No default passwords found.")
            return [] # Return an empty list if no findings

    def get_findings(self):
        """
        Returns the list of findings.

        Returns:
            list: A list of dictionaries, each representing a finding.
        """
        return self.findings


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description='Scans configuration files and running processes for the presence of default passwords.')
    parser.add_argument('--root-dir', '-r', default="/", help='The root directory to start the file system scan. Defaults to "/".')
    parser.add_argument('--no-process-scan', dest='process_scan', action='store_false', help='Disable scanning of running processes.')
    parser.set_defaults(process_scan=True)  # Enable process scanning by default
    parser.add_argument('--output', '-o', help='Output file for findings (JSON format).')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging (debug level).')
    return parser


def main():
    """
    Main function to execute the default password checker.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    checker = DefaultPasswordChecker(root_dir=args.root_dir, process_scan=args.process_scan)
    findings = checker.run_scan()

    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(findings, f, indent=4)
            logging.info(f"Findings saved to {args.output}")
        except Exception as e:
            logging.error(f"Error writing to output file {args.output}: {e}")
    elif findings:
        print(json.dumps(findings, indent=4)) # Print to standard output

if __name__ == "__main__":
    main()


# Usage Examples:
#
# 1. Run the scanner with default settings (scan / and running processes):
#    python misconfig-DefaultPasswordChecker.py
#
# 2. Run the scanner, specifying a different root directory:
#    python misconfig-DefaultPasswordChecker.py --root-dir /opt/my-application
#
# 3. Run the scanner without scanning running processes:
#    python misconfig-DefaultPasswordChecker.py --no-process-scan
#
# 4. Run the scanner and save the findings to a JSON file:
#    python misconfig-DefaultPasswordChecker.py --output findings.json
#
# 5. Run the scanner with verbose logging:
#    python misconfig-DefaultPasswordChecker.py --verbose
#
# 6. Run the scanner and output to a file and with verbose logging
#    python misconfig-DefaultPasswordChecker.py -o results.json -v