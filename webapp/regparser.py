import os, etldecoder
from dirs import *
from string_const import *


def isServiceDisabled():
    with open (AASVC_REG, encoding='UTF-16-LE') as f:
        aasvc = [line.rstrip() for line in f]
    isDisabled = False
    for line in aasvc:
        if "Start" in line and "0x4" in line:
            isDisabled = True
    
    return isDisabled



def singleAppCheck():
    with open (GETAA_PS, encoding='UTF-16-LE') as f:
        singleApp = [line.rstrip() for line in f]
    isSingleApp = False
    if singleApp:
        isSingleApp = True
    
    configs = []

    if isSingleApp:
        for line in singleApp[4 :]:
            if line.strip():
                config = line.split(" ", 3)
                configs.append(config)

    return isSingleApp, configs



def sLauncherCheck():
    with open (SL_REG, encoding='UTF-16-LE') as f:
        slauncher = [line.rstrip() for line in f]
    isShellLauncher = False
    for line in slauncher:
        if "Shell" in line and "REG_SZ" in line:
            isShellLauncher = True
            break      

    configs = []
    
    if isShellLauncher:
        lastIndex = 0        
        for line in slauncher:
            if "Shell Launcher\\" in line:
                currIndex = slauncher.index(line, lastIndex)
                user = line.split("\\")[5]
                shell = slauncher[currIndex + 1].replace("Shell", "").replace("REG_SZ", "").rstrip()
                appType = "Win32" if "0x1" in slauncher[currIndex+2] else "UWP"
                configs.append([user, shell, appType])
                lastIndex += currIndex + 1
    
    return isShellLauncher, configs



def diagCheck():
    with open (CFGMGR_REG, encoding='UTF-16-LE') as f:
        aadiag = [line.rstrip() for line in f]
    err     = None
    tStamp  = None

    for line in aadiag:
        if "Error" in line:
            err = line.replace("REG_DWORD", "").replace(" ", "", 1)
            code = err.replace("Error", "").strip()
            translation = etldecoder.translateError(code)
        if "Time" in line:
            tStamp = line.replace("REG_SZ", "")

    if err:
        return MSG_PROV.format(tStamp, err, translation)
    else:
        return None


def xmlCheckAndExtract():
    maXmlLines = ''
    slXmlLines = ''
    currIndex = None
    nextLine  = None

    with open (AACSP_REG, encoding='UTF-16-LE') as f:
        aacsp = [line.rstrip() for line in f]

    for line in aacsp:
        if "MultiAppXml" in line:
            firstLine = line.replace("MultiAppXml", "").replace("REG_SZ", "").strip()
            currIndex = aacsp.index(line)            
            maXmlLines += firstLine
            if '/AssignedAccessConfiguration' in firstLine:
                continue
            else:
                nextLine  = aacsp[currIndex + 1]
                while nextLine:         
                    maXmlLines += nextLine.rstrip()              
                    if "/AssignedAccessConfiguration" in nextLine:
                        break
                    currIndex += 1
                    nextLine = aacsp[currIndex + 1] 
        elif "ShellLauncherXml" in line:            
            firstLine = line.replace("ShellLauncherXml", "").replace("REG_SZ", "").strip()
            currIndex = aacsp.index(line)
            slXmlLines += firstLine
            if '/ShellLauncherConfiguration' in firstLine:
                continue
            else:
                nextLine  = aacsp[currIndex + 1]                  
                while nextLine:
                    nextLine.rstrip()
                    slXmlLines += nextLine
                    if '/ShellLauncherConfiguration' in nextLine:
                        break
                    currIndex += 1
                    nextLine = aacsp[currIndex + 1]  

    if maXmlLines:
        maXmlLines = maXmlLines.replace(">", ">\n")
    
    if slXmlLines:
        slXmlLines = slXmlLines.replace(">", ">\n")       


    return maXmlLines, slXmlLines 


def isAppInStartApps(app):    
    with open (GETSA_PS, encoding='UTF-16-LE') as f:
        startapps = [line.rstrip() for line in f]
    isAppInStartApps = False
    for line in startapps:
        if app in line:
            isAppInStartApps = True
    
    return isAppInStartApps



def isAppInstalledForUser(app, user):        
    with open (GETAP_PS, encoding='UTF-16-LE') as f:
        appxallusers = [line.rstrip() for line in f]
    isInstalledForUser = False
    packageFamilyName = (app.split("!",1))[0]
    for line in appxallusers:
        if packageFamilyName in line:
            userIndex = appxallusers.index(line) + 2
            for appLine in appxallusers[userIndex :]:
                if "IsResourcePackage" in appLine:
                    break
                elif user in appLine:
                    isInstalledForUser = True

    return isInstalledForUser



def kioskProfileScan():  
    with open (AA_REG, encoding='UTF-16-LE') as f:
        aaconfig = [line.rstrip() for line in f]
    profiles = []
    for line in aaconfig:
        if "ProfileId" in line and "DefaultProfileId" not in line and "GlobalProfileId" not in line:
            profileID = line.replace("ProfileId", "").replace("REG_SZ", "").replace(" ", "")
            profileType = aaconfig[aaconfig.index(line) + 2]
            if "0x0" in profileType:
                profileType = "Multi-App Kiosk"
            elif "0x1" in profileType:
                profileType = "Kiosk-Mode App"

            profile = (profileID, profileType)
            profiles.append(profile)

    return profiles



def appProfileScan():   
    with open (AA_REG, encoding='UTF-16-LE') as f:
        aaconfig = [line.rstrip() for line in f]

    profiles = kioskProfileScan()
    configs  = {}

    for profile in profiles:
        apps = []
        accounts = []
        lastIndex = 0
        for line in aaconfig:
            if profile[0] in line and "AllowedApps\\" in line:
                currIndex = aaconfig.index(line, lastIndex)                               
                appId     = aaconfig[currIndex + 1].replace("AppId", "").replace("REG_SZ", "").replace(" ", "")
                appType   = "UWP" if aaconfig[currIndex + 4].replace("AppType", "").replace("REG_DWORD", "").replace(" ", "") == "0x1" else "Win32"
                apps.append([appId, appType])
                lastIndex = currIndex + 1
            elif profile[0] in line and "DefaultProfileId" in line: 
                currIndex = aaconfig.index(line, lastIndex)
                if "GroupConfigs\\" in aaconfig[currIndex - 1]:
                    groupName = aaconfig[currIndex + 5].replace("Id", "").replace("REG_SZ", "").replace(" ", "")                    
                    groupType = aaconfig[currIndex + 7].replace("Type", "").replace("REG_DWORD", "").replace(" ", "")

                    if groupType == "0x64":
                        groupType = "Local"
                    elif groupType == "0x65":
                        groupType = "Domain"
                    elif groupType == "0x66":
                        groupType = "Azure AD"

                    accounts.append(["Group", groupName, groupType])
                elif "Configs\\" in aaconfig[currIndex - 1]:
                    userId = aaconfig[currIndex + 4].replace("Id", "").replace("REG_SZ", "").replace(" ", "")
                    userName = aaconfig[currIndex + 5].replace("Name", "").replace("REG_SZ", "").replace(" ", "")
                    userType = None

                    if userName:
                        if "AzureAD\\" in userName:
                            userType = "Azure AD"
                        elif "\\" in userName:
                            userType = "Domain"
                        else:
                            userType = "Local"
                    else:
                        userType = "Local"
                        isAutoLogon = False
                        with open (LOGON_REG, encoding='UTF-16-LE') as f:
                            wlogon = [line.rstrip() for line in f]
                        for line in wlogon:
                            if "AutoLogonSID" in line and userId in line:
                                isAutoLogon = True
                        if isAutoLogon:
                            userName = "AutoLogon Account"                            
                        else:
                            userName = MSG_BLANKUSER  

                    accounts.append(["User", userId, userName, userType])
                lastIndex = currIndex + 1
            elif profile[0] in line and "GlobalProfileId" in line:
                    accounts.append(["GlobalUser"])

        configs[profile] = [[apps, accounts]]

    return configs



def createReport():    
    errors = []
    report = []
    notInstalled = []
   
    if isServiceDisabled():
        errors.append(MSG_SVCDISABLED)

    provisioningError = diagCheck()
    if provisioningError:
        errors.append(provisioningError)    


    isSingleApp, singleAppProfiles = singleAppCheck()
    if isSingleApp:
        singleAppReport = MSG_SAFOUND.format(len(singleAppProfiles))
        for profile in singleAppProfiles:
            singleAppReport += MSG_SACONF.format(profile[1], profile[0], profile[2])
        
        report.append(singleAppReport)


    isShelllauncher, slauncherProfiles = sLauncherCheck()
    if isShelllauncher:
        slauncherReport = MSG_SLFOUND.format(len(slauncherProfiles))
        for profile in slauncherProfiles:
            slauncherReport += MSG_SLCONF.format(profile[0], profile[1], profile[2])
            if profile[2] == "UWP" and profile[1] not in notInstalled:
                isInStartApps = isAppInStartApps(profile[1])
                if not isInStartApps:
                    notInstalled.append(profile[1])
                    errors.append(MSG_STARTAPPNOTFOUND.format(profile[1]))
                else:
                    isInstalledForUser = isAppInstalledForUser(profile[1], profile[0])
                    if not isInstalledForUser:
                        errors.append(MSG_APPNOTREGISTERED.format(profile[0]))
        
        report.append(slauncherReport)


    configs = appProfileScan()
    for config in configs:        
        for profile in configs[config]:
            profileReport = MSG_PROFILEREPORT.format(config[0], config[1])
            apps = profile[0]
            accounts = profile[1]            
            appCount = 1
            accCount = 1            
            for app in apps:               
                profileReport += MSG_PROFILEAPP.format(appCount, app[0], app[1])
                appCount += 1
                if app[1] == "UWP" and app[0] not in notInstalled:
                    isInStartApps = isAppInStartApps(app[0])                
                    if not isInStartApps:
                        notInstalled.append(app[0])
                        errors.append(MSG_STARTAPPNOTFOUND.format(app[0]))
                    
            profileReport += (MSG_PROFILEASSIGNMENT)

            for account in accounts:
                if account[0] == "Group":
                    profileReport += MSG_GROUP.format(accCount, account[2], account [1])
                elif account[0] == "User":
                    profileReport += MSG_USER.format(accCount, account[3], account[2], account [1]) 
                    for app in apps:
                        if app[0] not in notInstalled and app[1] == "UWP":
                            isInstalledForUser = isAppInstalledForUser(app[0], account[1])                            
                            if not isInstalledForUser:
                                errors.append(MSG_APPNOTREGISTERED2.format(app[0], account[2], account[1]))
                elif account[0] == "GlobalUser":
                    profileReport += MSG_GLOBALUSER.format(accCount)
                accCount += 1
            report.append(profileReport) 

    return report, errors



def writeReport(report_id, etl_trace):
    report_file = "{}.txt".format(report_id)
    MultiAppXml, ShellLauncherXml = xmlCheckAndExtract()
    report, errors = createReport()
    with open (os.path.join(REPORT_DIR, report_file), 'w') as writer:
        writer.writelines(f'{DOUBLE_LINE}\nR E P O R T\n{DOUBLE_LINE}\n\n')
        if errors:
            writer.writelines(MSG_PROBLEMSFOUND)
            for error in errors:
                writer.writelines("{}".format(error))
            writer.writelines("\n")
        else:
            writer.writelines(MSG_NOPROBLEMSFOUND)

        writer.writelines(MSG_DETAILS)
        if report:
            for profileReport in report:
                writer.writelines("{}\n".format(profileReport))
        else:
            writer.writelines(MSG_NOPROFILEFOUND)

        writer.writelines("\n\n")

        if etl_trace:
            etl_report, errors = etldecoder.parseTrace(etl_trace)
            writer.writelines(MSG_ETL_ANALYSIS)
            if errors:
                writer.writelines(MSG_ETL_ERRFOUND )
                for error in errors:
                    writer.writelines(f'{error}\n')
            else:
                if etl_report:
                    writer.writelines(MSG_ETL_NOERRS )                
                    for item in etl_report:
                        writer.writelines(f"{item}\n")
                else:
                    writer.writelines(MSG_ETL_NOEVENTS)
            writer.writelines("\n")

        if MultiAppXml:
            writer.writelines(MSG_MULTIAPPXML)              
            writer.writelines(MultiAppXml)
            writer.writelines('\n\n')
        if ShellLauncherXml:           
            writer.writelines(MSG_SINGLEAPPXML)           
            writer.writelines(ShellLauncherXml)

        return report_file
