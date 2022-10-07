import os, etldecoder
import xml.etree.ElementTree as ET

def isServiceDisabled(UPLOAD_FOLDER):
    with open (os.path.join(UPLOAD_FOLDER, 'AssignedAccessManagerSvc_Reg.txt'), encoding='UTF-16-LE') as f:
        aasvc = [line.rstrip() for line in f]
    isDisabled = False
    for line in aasvc:
        if "Start" in line and "0x4" in line:
            isDisabled = True
    
    return isDisabled



def singleAppCheck(UPLOAD_FOLDER):
    with open (os.path.join(UPLOAD_FOLDER, 'Get-AssignedAccess.txt'), encoding='UTF-16-LE') as f:
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



def sLauncherCheck(UPLOAD_FOLDER):
    with open (os.path.join(UPLOAD_FOLDER, 'ShellLauncher_Reg.txt'), encoding='UTF-16-LE') as f:
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



def diagCheck(UPLOAD_FOLDER):
    with open (os.path.join(UPLOAD_FOLDER, 'ConfigManager_AssignedAccess_Reg.txt'), encoding='UTF-16-LE') as f:
        aadiag = [line.rstrip() for line in f]
    err     = None
    tStamp  = None

    for line in aadiag:
        if "Error" in line:
            err = line.replace("REG_DWORD", "")
        if "Time" in line:
            tStamp = line.replace("REG_SZ", "")

    if err:
        return '- A provisioning error was found - if the time doesn\'t correspond to the issue or is from too long ago it\'s likely irrelevant:\n\n{}\n{}\n'.format(tStamp, err)
    else:
        return None



def unescapeXML(xml):
    lastindex = 0
    with open (xml, 'r', encoding='utf-8') as reader:
        unescapedXML = reader.readlines()    

    for line in unescapedXML:
        if "<StartLayout>" in line:
            currIndex = unescapedXML.index(line, lastindex)
            unescapedXML[currIndex] = line.strip().replace("&lt;", "<").replace("&gt;", ">")
            lastindex = currIndex + 1
    
    with open (xml, 'w', encoding='utf-8') as writer:
        writer.writelines(unescapedXML)



def xmlCheckAndExtract(UPLOAD_FOLDER):
    maXmlLines = []
    slXmlLines = []
    currIndex = None
    nextLine  = None
    isMultiAppXML = False
    isShellLauncherXML = False

    with open (os.path.join(UPLOAD_FOLDER, 'AssignedAccessCsp_Reg.txt'), encoding='UTF-16-LE') as f:
        aacsp = [line.rstrip() for line in f]

    for line in aacsp:
        if "MultiAppXml" in line:
            firstLine = line.replace("MultiAppXml", "").replace("REG_SZ", "").strip().rstrip()
            currIndex = aacsp.index(line)
            nextLine  = aacsp[currIndex + 1]
            maXmlLines.append(firstLine)
            while nextLine:
                maXmlLines.append(nextLine)                
                if "/AssignedAccessConfiguration" in nextLine:
                    break
                currIndex += 1
                nextLine = aacsp[currIndex + 1] 
        elif "ShellLauncherXml" in line:            
            firstLine = line.replace("ShellLauncherXml", "").replace("REG_SZ", "").strip().rstrip()
            currIndex = aacsp.index(line)
            nextLine  = aacsp[currIndex + 1]
            slXmlLines.append(firstLine)  
            while nextLine:
                slXmlLines.append(nextLine)
                if '/ShellLauncherConfiguration' in nextLine:
                    break
                currIndex += 1
                nextLine = aacsp[currIndex + 1]           
    
    if maXmlLines:
        maxml = "".join(maXmlLines)        
        ET.register_namespace("v2", 'http://schemas.microsoft.com/AssignedAccess/201810/config')
        ET.register_namespace("v3", 'http://schemas.microsoft.com/AssignedAccess/2020/config')
        ET.register_namespace("", "http://schemas.microsoft.com/AssignedAccess/2017/config")
        root = ET.fromstring(maxml)
        tree = ET.ElementTree(root)
        ET.indent(tree, '  ')
        tree.write(os.path.join(UPLOAD_FOLDER, "MultiAppXML.xml"), encoding="utf-8", xml_declaration=True)
        unescapeXML(os.path.join(UPLOAD_FOLDER, "MultiAppXML.xml"))
        isMultiAppXML = True
    if slXmlLines:
        slxml = "".join(slXmlLines)        
        ET.register_namespace("v2", 'http://schemas.microsoft.com/ShellLauncher/2019/Configuration')
        ET.register_namespace("", "http://schemas.microsoft.com/ShellLauncher/2018/Configuration")
        root = ET.fromstring(slxml)
        tree = ET.ElementTree(root)
        ET.indent(tree, '  ')
        tree.write(os.path.join(UPLOAD_FOLDER, "ShellLauncherXML.xml"), encoding="utf-8", xml_declaration=True)
        unescapeXML(os.path.join(UPLOAD_FOLDER, "ShellLauncherXML.xml"))
        isShellLauncherXML = True
    
    return isMultiAppXML, isShellLauncherXML



def isAppInStartApps(app, UPLOAD_FOLDER):    
    with open (os.path.join(UPLOAD_FOLDER, 'Get-StartApps.txt'), encoding='UTF-16-LE') as f:
        startapps = [line.rstrip() for line in f]
    isAppInStartApps = False
    for line in startapps:
        if app in line:
            isAppInStartApps = True
    
    return isAppInStartApps



def isAppInstalledForUser(app, user, UPLOAD_FOLDER):        
    with open (os.path.join(UPLOAD_FOLDER, 'Get-AppxPackage-AllUsers.txt'), encoding='UTF-16-LE') as f:
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



def kioskProfileScan(UPLOAD_FOLDER):  
    with open (os.path.join(UPLOAD_FOLDER, 'AssignedAccess_Reg.txt'), encoding='UTF-16-LE') as f:
        aaconfig = [line.rstrip() for line in f]
    profiles = []
    for line in aaconfig:
        if "ProfileId" in line and "DefaultProfileId" not in line and "GlobalProfileId" not in line:
            profileID = line.replace("ProfileId", "").replace("REG_SZ", "").replace(" ", "")
            profileType = aaconfig[aaconfig.index(line) + 2]
            if "0" in profileType:
                profileType = "Multi-App Kiosk"
            elif "1" in profileType:
                profileType = "Kiosk-Mode App"

            profile = (profileID, profileType)
            profiles.append(profile)

    return profiles



def appProfileScan(UPLOAD_FOLDER):   
    with open (os.path.join(UPLOAD_FOLDER, 'AssignedAccess_Reg.txt'), encoding='UTF-16-LE') as f:
        aaconfig = [line.rstrip() for line in f]

    profiles = kioskProfileScan(UPLOAD_FOLDER)
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
                        with open (os.path.join(UPLOAD_FOLDER, 'Winlogon_Reg.txt'), encoding='UTF-16-LE') as f:
                            wlogon = [line.rstrip() for line in f]
                        for line in wlogon:
                            if "AutoLogonSID" in line and userId in line:
                                isAutoLogon = True
                        if isAutoLogon:
                            userName = "AutoLogon Account"                            
                        else:
                            userName = "[Username is blank and the SID was not found in the AutoLogon registry; could be a Domain account]"  

                    accounts.append(["User", userId, userName, userType])
                lastIndex = currIndex + 1
            elif profile[0] in line and "GlobalProfileId" in line:
                    accounts.append(["GlobalUser"])

        configs[profile] = [[apps, accounts]]

    return configs



def createReport(UPLOAD_FOLDER):    
    errors = []
    report = []
    notInstalled = []
   
    if isServiceDisabled(UPLOAD_FOLDER):
        errors.append("The AssignedAccessManager Service is Disabled.\n")

    provisioningError = diagCheck(UPLOAD_FOLDER)
    if provisioningError:
        errors.append(provisioningError)    


    isSingleApp, singleAppProfiles = singleAppCheck(UPLOAD_FOLDER)
    if isSingleApp:
        singleAppReport = "Found {} SingleApp Configuration(s):".format(len(singleAppProfiles))
        for profile in singleAppProfiles:
            singleAppReport += "User Name: {}\nUser SID: {}\nAUMID: {}\n".format(profile[1], profile[0], profile[2])
        
        report.append(singleAppReport)


    isShelllauncher, slauncherProfiles = sLauncherCheck(UPLOAD_FOLDER)
    if isShelllauncher:
        slauncherReport = "Found {} ShellLauncher Configuration(s):\n".format(len(slauncherProfiles))
        for profile in slauncherProfiles:
            slauncherReport += "User: {}\nShell: {}\nAppType: {}\n".format(profile[0], profile[1], profile[2])
            if profile[2] == "UWP" and profile[1] not in notInstalled:
                isInStartApps = isAppInStartApps(profile[1], UPLOAD_FOLDER)
                if not isInStartApps:
                    notInstalled.append(profile[1])
                    errors.append("Application {} was not found in Get-StartApps output. Check if it is installed or otherwise if the AUMID is correctly spelled\n".format(profile[1]))
                else:
                    isInstalledForUser = isAppInstalledForUser(profile[1], profile[0], UPLOAD_FOLDER)
                    if not isInstalledForUser:
                        errors.append("App {} not registered/installed for user {}.\n".format(profile[0]))
        
        report.append(slauncherReport)


    configs = appProfileScan(UPLOAD_FOLDER)
    for config in configs:        
        for profile in configs[config]:
            profileReport = "\n\nProfile {} of type {} has the following allowed apps:\n\n".format(config[0], config[1])
            apps = profile[0]
            accounts = profile[1]            
            appCount = 1
            accCount = 1            
            for app in apps:               
                profileReport += "{}) {} | {} App\n".format(appCount, app[0], app[1])
                appCount += 1
                if app[1] == "UWP" and app[0] not in notInstalled:
                    isInStartApps = isAppInStartApps(app[0], UPLOAD_FOLDER)                
                    if not isInStartApps:
                        notInstalled.append(app[0])
                        errors.append("- Application {} was not found in Get-StartApps output. Check if it is installed or otherwise if the AUMID is correctly spelled\n".format(app[0]))
                    
            profileReport += ("\nAnd is assigned to the following accounts:\n\n")

            for account in accounts:
                if account[0] == "Group":
                    profileReport += "{}) {} Group: {}\n".format(accCount, account[2], account [1])
                elif account[0] == "User":
                    profileReport += ("{}) {} User: {} with ID {}\n".format(accCount, account[3], account[2], account [1]))  
                    for app in apps:
                        if app[0] not in notInstalled and app[1] == "UWP":
                            isInstalledForUser = isAppInstalledForUser(app[0], account[1], UPLOAD_FOLDER)                            
                            if not isInstalledForUser:
                                errors.append("- App {} not registered/installed for user {} with SID: {}.\n".format(app[0], account[2], account[1]))
                elif account[0] == "GlobalUser":
                    profileReport += "{}) Global User".format(accCount)
                accCount += 1
            report.append(profileReport) 

    return report, errors



def showReport(UPLOAD_FOLDER, report_id, etl_trace):
    report_file = "{}.txt".format(report_id)

    isMultiAppXml, isShellLauncherXml = xmlCheckAndExtract(UPLOAD_FOLDER)
    report, errors = createReport(UPLOAD_FOLDER)
    double_line = '======================================================'
    single_line = '------------------------------------------------------'
    with open (os.path.join('reports', report_file), 'w') as writer:
        writer.writelines(f'{double_line}\nR E P O R T\n{double_line}\n\n')
        if errors:
            writer.writelines(f"Problems found\n{single_line}")
            for error in errors:
                writer.writelines("{}".format(error))
            writer.writelines("\n")
        else:
            writer.writelines("No problems were found.\n\n")

        writer.writelines(f"{double_line}\nDetails\n{double_line}\n")
        for profileReport in report:
            writer.writelines("{}\n".format(profileReport))

        writer.writelines("\n")

        if etl_trace:
            etl_report = etldecoder.parseTrace(UPLOAD_FOLDER, etl_trace, False)
            writer.writelines(f'{double_line}\nETL Trace Analysis\n{double_line}\n\n')
            for item in etl_report:
                writer.writelines(f"{item}\n")
            writer.writelines("\n")

        if isMultiAppXml:
            lineCount = 0
            longestLine = 0
            writer.writelines(f'{double_line}\nFound and Extracted Multi-App Kiosk XML\n{double_line}\n')  
            with open (os.path.join(UPLOAD_FOLDER, 'MultiAppXML.xml'), 'r') as f:
                for line in f:
                    lineCount += 1
                    if len(line) > longestLine:
                        longestLine = len(line)          
            writer.writelines('{}{}\n'.format(lineCount + 1, longestLine))
            with open (os.path.join(UPLOAD_FOLDER, 'MultiAppXML.xml'), 'r') as f:
                for line in f:
                    writer.writelines(line)                
        
        if isShellLauncherXml:
            lineCount = 0
            longestLine = 0
            writer.writelines(f'Found and Extracted Shell Launcher XML:\n{double_line}')
            with open (os.path.join(UPLOAD_FOLDER, 'ShellLauncherXML.xml'), 'r') as f:
                for line in f:
                    lineCount += 1
                    if len(line) > longestLine:
                        longestLine = len(line)           
            writer.writelines('{}{}\n'.format(lineCount, longestLine))            
            with open (os.path.join(UPLOAD_FOLDER, 'ShellLauncherXML.xml'), 'r') as f:
                for line in f:
                    writer.writelines(line) 

        return report_file