from distutils.command.upload import upload
import os, random, string
from flask import Flask, flash, request, redirect, render_template

import xml.etree.ElementTree as ET

path = os.getcwd()
UPLOAD_FOLDER = os.path.join(path, 'uploads')

if not os.path.isdir(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)

def isServiceDisabled():
    with open (os.path.join(UPLOAD_FOLDER, 'AssignedAccessManagerSvc_Reg.txt'), encoding='UTF-16-LE') as f:
        aasvc = [line.rstrip() for line in f]
    isDisabled = False
    for line in aasvc:
        if "Start" in line:
            if "0x4" in line:
                isDisabled = True
    
    return isDisabled



def singleAppCheck():
    with open (os.path.join(UPLOAD_FOLDER, 'Get-AssignedAccess.txt'), encoding='UTF-16-LE') as f:
        singleApp = [line.rstrip() for line in f]
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
    with open (os.path.join(UPLOAD_FOLDER, 'ShellLauncher_Reg.txt'), encoding='UTF-16-LE') as f:
        slauncher = [line.rstrip() for line in f]
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
        return "<p>- A provisioning error was found - if the time doesn't correspond to the issue or is from too long ago it's likely irrelevant</p><p>{}</p><p>{}</p>".format(tStamp, err)
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

    with open (os.path.join(UPLOAD_FOLDER, 'AssignedAccessCsp_Reg.txt'), encoding='UTF-16-LE') as f:
        aacsp = [line.rstrip() for line in f]

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
    with open (os.path.join(UPLOAD_FOLDER, 'Get-StartApps.txt'), encoding='UTF-16-LE') as f:
        startapps = [line.rstrip() for line in f]
    isAppInStartApps = False
    for line in startapps:
        if app in line:
            isAppInStartApps = True
    
    return isAppInStartApps



def isAppInstalledForUser(app, user):        
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



def kioskProfileScan():  
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



def appProfileScan():   
    with open (os.path.join(UPLOAD_FOLDER, 'AssignedAccess_Reg.txt'), encoding='UTF-16-LE') as f:
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
        singleAppReport = "<h3>Found {} SingleApp Configuration(s):</h3>".format(len(singleAppProfiles))
        for profile in singleAppProfiles:
            singleAppReport += "<p>User Name: {}</p>User SID: {}</p>AUMID: {}</p>".format(profile[1], profile[0], profile[2])
        
        report.append(singleAppReport)


    isShelllauncher, slauncherProfiles = sLauncherCheck()
    if isShelllauncher:
        slauncherReport = "<h3>Found {} ShellLauncher Configuration(s):</h3>".format(len(slauncherProfiles))
        for profile in slauncherProfiles:
            slauncherReport += "<p>User: {}</p>Shell: {}</p>AppType: {}</p>".format(profile[0], profile[1], profile[2])
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
            profileReport = "<h3>Profile {} of type {} has the following allowed apps:</h3>".format(config[0], config[1])
            apps = profile[0]
            accounts = profile[1]            
            appCount = 1
            accCount = 1            
            for app in apps:               
                profileReport += "<p>{}) {} | {} App</p>".format(appCount, app[0], app[1])
                appCount += 1
                if app[1] == "UWP" and app[0] not in notInstalled:
                    isInStartApps = isAppInStartApps(app[0])                
                    if not isInStartApps:
                        notInstalled.append(app[0])
                        errors.append("<p>- Application {} was not found in Get-StartApps output. Check if it is installed or otherwise if the AUMID is correctly spelled</p>".format(app[0]))
                    
            profileReport += ("<h3>And is assigned to the following accounts:</h3>")

            for account in accounts:
                if account[0] == "Group":
                    profileReport += "<p>{}) {} Group: {}</p>".format(accCount, account[2], account [1])
                elif account[0] == "User":
                    profileReport += ("<p>{}) {} User: {} with ID {}</p>".format(accCount, account[3], account[2], account [1]))  
                    for app in apps:
                        if app[0] not in notInstalled and app[1] == "UWP":
                            isInstalledForUser = isAppInstalledForUser(app[0], account[1])                            
                            if not isInstalledForUser:
                                errors.append("<p>- App {} not registered/installed for user {} with SID: {}.</p>".format(app[0], account[2], account[1]))
                elif account[0] == "GlobalUser":
                    profileReport += "<p>{}) Global User</p>".format(accCount)
                accCount += 1
            report.append(profileReport) 

    return report, errors



def showReport():
    xmlCheckAndExtract()
    report, errors = createReport()

    letters = string.ascii_lowercase
    report_id = ( ''.join(random.choice(letters) for i in range(10)) )
    print(os.listdir())
    with open (os.path.join('templates', '{}.html'.format(report_id)), 'w') as writer:        
        writer.writelines("<h1>Report</h1>")
        for profileReport in report:
            writer.writelines("<p>\n{}\n</p>".format(profileReport))

        if errors:
            writer.writelines("<h1>\n\nProblems found:\n</h1>")
            for error in errors:
                writer.writelines("{}".format(error))
            writer.writelines("\n")
        else:
            writer.writelines("<h1>No problems were found.</h1>")
    
    return "{}.html".format(report_id)

def remove_template(template):
    os.remove(template)
    return

app=Flask(__name__)

app.secret_key = "secret key"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = set(['txt'])
necessary_files = ['AssignedAccess_Reg', 'AssignedAccessCsp_Reg', 'AssignedAccessManagerSvc_Reg', 'ConfigManager_AssignedAccess_Reg', 'Get-AppxPackage-AllUsers', 'Get-AssignedAccess', 'ShellLauncher_Reg', 'Get-StartApps']
uploaded_files = []

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/')
def upload_form():
    return render_template('upload.html')

@app.route('/', methods=['POST'])
def upload_file():
    if request.method == 'POST':

        if 'files[]' not in request.files:
            flash('No file part')
            return redirect(request.url)

        files = request.files.getlist('files[]')        
        for file in files:           
            if file and allowed_file(file.filename):            
                filename = file.filename.rsplit("/")[-1]          
                for necessaryfile in necessary_files:
                    if necessaryfile == filename.replace(".txt", ""):                               
                        if necessaryfile not in uploaded_files:
                            uploaded_files.append(necessaryfile) 
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))                

        tmpl = showReport()
        return render_template(tmpl)

if __name__ == "__main__":
    app.run(host='127.0.0.1',port=5000,debug=False,threaded=True)