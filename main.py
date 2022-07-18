import xml.etree.ElementTree as ET


with open ('AssignedAccess_Reg.txt', encoding='UTF-16-LE') as f:
    aaconfig = [line.rstrip() for line in f]

with open ('ConfigManager_AssignedAccess_Reg.txt', encoding='UTF-16-LE') as f:
    aadiag = [line.rstrip() for line in f]

with open ('ShellLauncher_Reg.txt', encoding='UTF-16-LE') as f:
    slauncher = [line.rstrip() for line in f]

with open ('AssignedAccessManagerSvc_Reg.txt', encoding='UTF-16-LE') as f:
    aasvc = [line.rstrip() for line in f]

with open ('AssignedAccessCsp_Reg.txt', encoding='UTF-16-LE') as f:
    aacsp = [line.rstrip() for line in f]

with open ('startapps.txt', encoding='UTF-16-LE') as f:
    startapps = [line.rstrip() for line in f]

with open ('Get-AppxPackage-AllUsers.txt', encoding='UTF-16-LE') as f:
    appxallusers = [line.rstrip() for line in f]

with open ('Get-AssignedAccess.txt', encoding='UTF-16-LE') as f:
    singleApp = [line.rstrip() for line in f]



def isServiceDisabled():
    isDisabled = False
    for line in aasvc:
        if "Start" in line:
            if "0x4" in line:
                isDisabled = True
    
    return isDisabled



def singleAppCheck():
    isSingleApp = False
    if not "does not exist" in singleApp[0]:
        isSingleApp = True
    
    configs = []

    if isSingleApp:
        for line in singleApp[4 :]:
            if line.strip():
                config = line.split(" ", 3)
                configs.append(config)

    return isSingleApp, configs



def sLauncherCheck():
    isShellLauncher = False
    if not "does not exist" in slauncher[0]:
        isShellLauncher = True        
    
    if isShellLauncher:
        lastIndex = 0
        configs = []
        for line in slauncher:
            if "Shell Launcher\\" in line:
                currIndex = slauncher.index(line, lastIndex)
                user = line.split("\\")[5]
                shell = slauncher[currIndex + 1].replace("Shell", "").replace("REG_SZ", "").replace(" ", "")
                appType = "Win32" if "0x1" in slauncher[currIndex+2] else "UWP"
                configs.append([user, shell, appType])
                lastIndex += currIndex + 1
    
    return isShellLauncher, configs



def diagCheck():
    err     = None
    tStamp  = None

    for line in aadiag:
        if "Error" in line:
            err = line.replace("REG_DWORD", "")
        if "Time" in line:
            tStamp = line.replace("REG_SZ", "")

    if err:
        return "A provisioning error was found - if the time doesn't correspond to the issue or is from too long ago it's likely irrelevant\n\n{}\n{}\n".format(tStamp, err)
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



def xmlCheckAndExtract():
    xmlLines = []
    currIndex = None
    nextLine  = None

    for line in aacsp:
        if "MultiAppXml" in line or "ShellLauncherXml" in line:
            firstLine = line.replace("MultiAppXml", "").replace("ShellLauncherXml", "").replace("REG_SZ", "").strip().rstrip()
            currIndex = aacsp.index(line)
            nextLine  = aacsp[currIndex + 1]
            xmlLines.append(firstLine)  
    while nextLine:
        xmlLines.append(nextLine)
        currIndex += 1
        nextLine = aacsp[currIndex + 1]           
    
    if xmlLines:
        xml = "".join(xmlLines)
        ET.register_namespace("v2", 'http://schemas.microsoft.com/AssignedAccess/201810/config')
        ET.register_namespace("v3", 'http://schemas.microsoft.com/AssignedAccess/2020/config')
        ET.register_namespace("", "http://schemas.microsoft.com/AssignedAccess/2017/config")
        root = ET.fromstring(xml)
        tree = ET.ElementTree(root)
        ET.indent(tree, '  ')
        tree.write("extractedXML.xml", encoding="utf-8", xml_declaration=True)
        unescapeXML("extractedXML.xml")
    else:
        return None



def isAppInStartApps(app):
    isAppInStartApps = False
    for line in startapps:
        if app in line:
            isAppInStartApps = True
    
    return isAppInStartApps



def isAppInstalledForUser(app, user):    
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



def appProfileScan():
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

                    if "AzureAD\\" in userName:
                        userType = "Azure AD"
                    elif "\\" in userName:
                        userType = "Domain"
                    else:
                        userType = "Local"                    

                    accounts.append(["User", userId, userName, userType])
                lastIndex = currIndex + 1
            elif profile[0] in line and "GlobalProfileId" in line:
                    accounts.append(["GlobalUser", "Fill"])

        configs[profile] = [[apps, accounts]]

    return configs



def createReport():    
    errors = []
    report = []
    notInstalled = []
   
    if isServiceDisabled():
        errors.append("The AssignedAccessManager Service is Disabled.\n")

    provisioningError = diagCheck()
    if provisioningError:
        errors.append(provisioningError)    


    isSingleApp, singleAppProfiles = singleAppCheck()
    if isSingleApp:
        singleAppReport = "\n\nFound {} SingleApp Configuration(s):\n\n".format(len(singleAppProfiles))
        for profile in singleAppProfiles:
            singleAppReport += "User Name: {}\nUser SID: {}\nAUMID: {}\n".format(profile[1], profile[0], profile[2])
        
        report.append(singleAppReport)


    isShelllauncher, slauncherProfiles = sLauncherCheck()
    if isShelllauncher:
        slauncherReport = "\n\nFound {} ShellLauncher Configuration(s):\n\n".format(len(slauncherProfiles))
        for profile in slauncherProfiles:
            slauncherReport += "User: {}\nShell: {}\nAppType: {}\n".format(profile[0], profile[1], profile[2])
            if profile[2] == "UWP" and profile[1] not in notInstalled:
                isInStartApps = isAppInStartApps(profile[1])
                if not isInStartApps:
                    notInstalled.append(profile[1])
                    errors.append("Application {} was not found in Get-StartApps output. Check if it is installed or otherwise if the AUMID is correctly spelled\n".format(profile[1]))
                else:
                    isInstalledForUser = isAppInstalledForUser(profile[1], profile[0])
                    if not isInstalledForUser:
                        errors.append("App {} not registered/installed for user {}.\n".format(profile[0]))
        
        report.append(slauncherReport)


    configs = appProfileScan()
    for config in configs:        
        for profile in configs[config]:
            profileReport = "Profile {} of type {} has the following allowed apps:\n\n".format(config[0], config[1])
            apps = profile[0]
            accounts = profile[1]            
            appCount = 1
            accCount = 1            
            for app in apps:               
                profileReport += "{}) {} | {} App\n".format(appCount, app[0], app[1])
                appCount += 1
                if app[1] == "UWP" and app[0] not in notInstalled:
                    isInStartApps = isAppInStartApps(app[0])                
                    if not isInStartApps:
                        notInstalled.append(app[0])
                        errors.append("Application {} was not found in Get-StartApps output. Check if it is installed or otherwise if the AUMID is correctly spelled\n".format(app[0]))
                    
            profileReport += ("\n\n And is assigned to the following accounts:\n\n")

            for account in accounts:
                if account[0] == "Group":
                    profileReport += "{}) {} Group: {}\n".format(accCount, account[2], account [1])
                elif account[0] == "User":
                    profileReport += ("{}) {} User: {} with ID {}\n".format(accCount, account[3], account[2], account [1]))  
                    for app in apps:
                        if app[0] not in notInstalled and app[1] == "UWP":
                            isInstalledForUser = isAppInstalledForUser(app[0], account[1])                            
                            if not isInstalledForUser:
                                errors.append("App {} not registered/installed for user {} with SID: {}.\n".format(app[0], account[2], account[1]))
                elif account[0] == "GlobalUser":
                    profileReport += "{}) Global User\n".format(accCount)
                accCount += 1
            report.append(profileReport) 

    return report, errors



def showReport():
    xmlCheckAndExtract()
    report, errors = createReport()

    for profileReport in report:
        print("{}\n".format(profileReport))

    if errors:
        print("\n\nProblems found:\n")
        for error in errors:
            print("- {}".format(error))
        print("\n")
    else:
        print("No problems were found.")


showReport()