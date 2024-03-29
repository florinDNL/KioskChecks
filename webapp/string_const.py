DOUBLE_LINE = "======================================================"
SINGLE_LINE = "------------------------------------------------------"


MSG_PROV                = "- Provisioning error found - if the time doesn\'t correspond to the issue or is from too long ago it\'s likely irrelevant:\n\n{}\n{} | Error Text(s): {}\n"
MSG_SVCDISABLED         = "The AssignedAccessManager Service is Disabled.\n"
MSG_BLANKUSER           = "[Username is blank and the SID was not found in the AutoLogon registry; could be a Domain account]"
MSG_SAFOUND             = "Found {} SingleApp Configuration(s):"
MSG_SACONF              = "User Name: {}\nUser SID: {}\nAUMID: {}\n"
MSG_SLFOUND             = "Found {} ShellLauncher Configuration(s):\n"
MSG_SLCONF              = "User: {}\nShell: {}\nAppType: {}\n"
MSG_STARTAPPNOTFOUND    = "Application {} was not found in Get-StartApps output. Check if it is installed or otherwise if the AUMID is correctly spelled\n"
MSG_APPNOTREGISTERED    = "App {} not registered/installed for user {}.\n"
MSG_APPNOTREGISTERED2   = "- App {} not registered/installed for user {} with SID: {}.\n"
MSG_PROFILEREPORT       = "\n\nProfile {} of type {} has the following allowed apps:\n\n"
MSG_PROFILEAPP          = "{}) {} | {} App\n"
MSG_PROFILEASSIGNMENT   = "\nAnd is assigned to the following accounts:\n\n"
MSG_GROUP               = "{}) {} Group: {}\n"
MSG_USER                = "{}) {} User: {} with ID {}\n"
MSG_GLOBALUSER          = "{}) Global User"
MSG_NOPROBLEMSFOUND     = "No problems were found.\n\n"
MSG_NOPROFILEFOUND      = "No applied Kiosk Profile found on this machine."
MSG_PROBLEMSFOUND       = f"Problems found\n{SINGLE_LINE}\n"
MSG_DETAILS             = f"{DOUBLE_LINE}\nDetails\n{DOUBLE_LINE}\n"
MSG_ETL_ANALYSIS        = f"{DOUBLE_LINE}\nETL Trace Analysis\n{DOUBLE_LINE}\n\n"
MSG_ETL_ERRFOUND        = f"Errors found. Code translation:\n{SINGLE_LINE}\n"
MSG_ETL_ALLEVENTS       = f"\n\nAll Assigned Access Events:\n{SINGLE_LINE}\n"
MSG_ETL_NOERRS          = f"No errors found. Dumping all AssignedAccess and Logon Events:\n\n"
MSG_ETL_NOEVENTS        = "No AssignedAccess events found."
MSG_MULTIAPPXML         = f"\n{DOUBLE_LINE}\nFound and Extracted Multi-App Kiosk XML\n{DOUBLE_LINE}\n"
MSG_SINGLEAPPXML        = f"\n{DOUBLE_LINE}\nFound and Extracted Shell Launcher XML:\n{DOUBLE_LINE}\n"
MSG_UNKNOWNERR          = "Unknown Error"
MSG_ERRORSTRING         = "ERROR {} | {} | Thread ID: {} | Process ID: {} | Activity: {} | Event: {}"
MSG_SUCCESSSTRING       = "SUCCESS | {} | Thread ID: {} | Process ID: {} | Activity: {} | Event: {}"

FLASH_MISSINGFILES      = "You are missing the following files in the LogonLog folder: "
FLASH_NOFOLDER          = "No folder selected"
FLASH_INVALIDCASENO     = "Invalid case number"
FLASH_PROCESSING        = "Your files are being analyzed, please wait"
FLASH_MISSINGFILESLIST  = "{}.txt, "
FLASH_INTERNALERR       = "An error occured while parsing the data."