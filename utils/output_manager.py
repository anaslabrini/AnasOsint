# utils/output_manager.py

import os
import datetime
from colorama import Fore, Style, init

# Initialize colorama for colored console output
init(autoreset=True)

# Report control flags
save_report = False
report_path = None


def set_report(save=False, path="report.txt"):
    """Configure report saving and initialize file with header and timestamp."""
    global save_report, report_path
    save_report = save
    report_path = path
    if save_report:
        # Create directory if necessary
        dirnm = os.path.dirname(report_path)
        if dirnm:
            os.makedirs(dirnm, exist_ok=True)
        # Write header
        header = (
            f"=== Report Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n\n"
        )
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(header)
        info(f"Report initialized: {report_path}")


def _timestamp():
    """Return a formatted current timestamp string."""
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def write_to_report(message):
    """Write a timestamped message to the report file if saving is enabled."""
    if save_report and report_path:
        with open(report_path, 'a', encoding='utf-8') as f:
            f.write(f"[{_timestamp()}] {message}\n")


def info(message):
    msg = f"[INFO] {message}"
    print(f"{Fore.CYAN}{msg}{Style.RESET_ALL}")
    write_to_report(msg)


def success(message):
    msg = f"[SUCCESS] {message}"
    print(f"{Fore.GREEN}{msg}{Style.RESET_ALL}")
    write_to_report(msg)


def warning(message):
    msg = f"[WARNING] {message}"
    print(f"{Fore.YELLOW}{msg}{Style.RESET_ALL}")
    write_to_report(msg)


def error(message):
    msg = f"[ERROR] {message}"
    print(f"{Fore.RED}{msg}{Style.RESET_ALL}")
    write_to_report(msg)
