import os

PARENT_DIR = os.path.abspath(os.path.join(os.getcwd(), os.pardir))
DIRECTORY_TO_SERVE_PATH = os.path.join(PARENT_DIR, 'kaDownload')
REPORT_DIR = os.path.join(PARENT_DIR, 'reports')
UPLOAD_FOLDER = os.path.join(PARENT_DIR, 'upload')
REPORT_HISTORY = os.path.join(PARENT_DIR, 'report_history.txt')
UTIL_DIR = os.path.join(PARENT_DIR, 'util')

def dirCheck():
    print(os.getcwd())
    if not os.path.exists(DIRECTORY_TO_SERVE_PATH):
        os.mkdir(DIRECTORY_TO_SERVE_PATH)
    if not os.path.exists(REPORT_DIR):
        os.mkdir(REPORT_DIR)
    if not os.path.exists(REPORT_HISTORY):
        open(REPORT_HISTORY, 'a').close()
    