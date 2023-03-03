import os

PARENT_DIR                  = os.path.abspath(os.path.join(os.getcwd(), os.pardir))
DIRECTORY_TO_SERVE_PATH     = os.path.join(PARENT_DIR, 'kaDownload')
REPORT_DIR                  = os.path.join(PARENT_DIR, 'reports')
UPLOAD_FOLDER               = os.path.join(PARENT_DIR, 'upload')
REPORT_HISTORY              = os.path.join(PARENT_DIR, 'report_history.txt')
UTIL_DIR                    = os.path.join(PARENT_DIR, 'util')

AASVC_REG   = os.path.join(UPLOAD_FOLDER, 'AssignedAccessManagerSvc_Reg.txt')
SL_REG      = os.path.join(UPLOAD_FOLDER, 'ShellLauncher_Reg.txt')
CFGMGR_REG  = os.path.join(UPLOAD_FOLDER, 'ConfigManager_AssignedAccess_Reg.txt')
AACSP_REG   = os.path.join(UPLOAD_FOLDER, 'AssignedAccessCsp_Reg.txt')
AA_REG      = os.path.join(UPLOAD_FOLDER, 'AssignedAccess_Reg.txt')
LOGON_REG   = os.path.join(UPLOAD_FOLDER, 'Winlogon_Reg.txt')
GETAA_PS    = os.path.join(UPLOAD_FOLDER, 'Get-AssignedAccess.txt')
GETSA_PS    = os.path.join(UPLOAD_FOLDER, 'Get-StartApps.txt')
GETAP_PS    = os.path.join(UPLOAD_FOLDER, 'Get-AppxPackage-AllUsers.txt')

TRACEFMT    = os.path.join(UTIL_DIR, 'tracefmt.exe')
ERR         = os.path.join(UTIL_DIR, 'err.exe')  
TMFOUTPUT   = os.path.join(UPLOAD_FOLDER, 'tmf_trace.txt')


def dirCheck():
    if not os.path.exists(DIRECTORY_TO_SERVE_PATH):
        os.mkdir(DIRECTORY_TO_SERVE_PATH)
    if not os.path.exists(REPORT_DIR):
        os.mkdir(REPORT_DIR)
    if not os.path.exists(REPORT_HISTORY):
        open(REPORT_HISTORY, 'a').close()
    