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



def isServiceDisabled():
    isDisabled = False
    for line in aasvc:
        if "Start" in line:
            if "0x4" in line:
                isDisabled = True
    
    return isDisabled



def sLauncherCheck():
    isShellLauncher = False
    count = 0
    if not "does not exist" in slauncher[0]:
        isShellLauncher = True        
    
    return isShellLauncher
    


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
        return True
    else:
        return None



def kioskProfileScan():
    profiles = []
    for line in aaconfig:
        if "ProfileId" in line and "DefaultProfileId" not in line and "GlobalProfileId" not in line:
            profileID = line.replace("ProfileId", "").replace("REG_SZ", "").replace(" ", "")
            profileType = aaconfig[aaconfig.index(line) + 2]
            isMultiAppKiosk = False
            isKioskModeApp  = False
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
        currIndex = 0
        for line in aaconfig:
            if profile[0] in line and "AllowedApps\\" in line:
                currIndex = aaconfig.index(line, currIndex) 
                print(currIndex)                                
                appId     = aaconfig[currIndex + 1].replace("AppId", "").replace("REG_SZ", "").replace(" ", "")
                appType   = "UWP" if aaconfig[currIndex + 4].replace("AppType", "").replace("REG_DWORD", "").replace(" ", "") == "0x1" else "Win32"
                apps.append([appId, appType])
            elif profile[0] in line and "DefaultProfileId" in line: 
                currIndex = aaconfig.index(line, currIndex)
                print(currIndex)
                if "GroupConfigs\\" in aaconfig[currIndex - 1]:
                    groupName = aaconfig[currIndex + 5].replace("Id", "").replace("REG_SZ", "").replace(" ", "")                    
                    groupType = aaconfig[currIndex + 7].replace("Type", "").replace("REG_DWORD", "").replace(" ", "")
                    accounts.append(["Group", groupName, groupType])
                    print(groupName)
                elif "Configs\\" in aaconfig[currIndex - 1]:
                    userId = aaconfig[currIndex + 4].replace("Id", "").replace("REG_SZ", "").replace(" ", "")
                    userName = aaconfig[currIndex + 5].replace("Name", "").replace("REG_SZ", "").replace(" ", "")
                    userType = aaconfig[currIndex + 6].replace("Type", "").replace("REG_DWORD", "").replace(" ", "")
                    accounts.append(["User", userId, userName, userType])
                    print(userName)
            elif profile[0] in line and "GlobalProfileId" in line:
                    accounts.append(["GlobalUser", "Fill"])

        configs[profile] = [[apps, accounts]]

    return configs



def problemCheck():    
    errors = []
    report = []
   
    if isServiceDisabled():
        errors.append("The AssignedAccessManager Service is Disabled.\n")

    provisioningError = diagCheck()
    if provisioningError:
        errors.append(provisioningError)    


    configs = appProfileScan()
    for config in configs:
        print("Profile {} of type {} has the following allowed apps:\n".format(config[0], config[1]))
        for profile in configs[config]:
            apps = profile[0]
            accounts = profile[1]            
            appCount = 1
            accCount = 1
            notInstalled = []
            for app in apps:               
                print("{}) {} | {} App".format(appCount, app[0], app[1]))
                appCount += 1
                if app[1] == "UWP":
                    isError = True
                    for line in startapps:
                        if app[0] in line:
                            isError = False                
                    if isError:
                        notInstalled.append(app[0])
                        errors.append("Application {} was not found in Get-StartApps output. Check if it is installed or otherwise if the AUMID is correctly spelled\n".format(app[0]))
                    
            print("\n And is assigned to the following accounts:\n")

            for account in accounts:
                if account[0] == "Group":
                    print("{}) Group {} of type {}".format(accCount, account[1], account [2]))
                elif account[0] == "User":
                    print("{}) User {} of type {} with the name {}".format(accCount, account[1], account[3], account [2]))  
                    for app in apps:
                        if app[0] not in notInstalled and app[1] == "UWP":
                            isInstalledForUser = False
                            packageFamilyName = (app[0].split("!",1))[0]
                            for line in appxallusers:
                                if packageFamilyName in line:
                                    userIndex = appxallusers.index(line) + 2
                                    for appLine in appxallusers[userIndex :]:
                                        if "IsResourcePackage" in appLine:
                                            break
                                        elif account[1] in appLine:
                                            isInstalledForUser = True
                            
                            if not isInstalledForUser:
                                errors.append("App {} not registered/installed for user {} with SID: {}.\n".format(app[0], account[2], account[1]))
                elif account[0] == "GlobalUser":
                    print("Global User")

                accCount += 1                     
    return errors



def createReport():
    xmlCheckAndExtract()
    errors = problemCheck()
    if errors:
        print("\n\nProblems found:\n")
        for error in errors:
            print("- {}".format(error))
        print("\n")
    else:
        print("No problems were found.")

appProfileScan()