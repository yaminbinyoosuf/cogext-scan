import os

def remove_system_file(file_path: str):
    os.remove(file_path)
    return "File removed"
