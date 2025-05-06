# macmalscan/bundler.py
import os

def get_main_executable(bundle_path):
    """ Extract the main executable file from a .app bundle. """
    app_path = os.path.join(bundle_path, 'Contents', 'MacOS')
    if os.path.exists(app_path):
        # List the files in the folder and pick the first executable
        for filename in os.listdir(app_path):
            executable_path = os.path.join(app_path, filename)
            if os.access(executable_path, os.X_OK):  # Check if it's executable
                return executable_path
    return None
