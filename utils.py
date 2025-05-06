# macmalscan/utils.py
import subprocess
import os

def extract_strings(file_path):
    """ Extract strings from a file using the `strings` command. """
    try:
        result = subprocess.run(['strings', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.splitlines()
    except Exception as e:
        print(f"Error extracting strings: {e}")
        return []

def ensure_dir(directory):
    """ Ensure a directory exists. """
    if not os.path.exists(directory):
        os.makedirs(directory)
