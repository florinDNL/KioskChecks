import subprocess, os


def decodeEtlTrace(folder, etl_trace):
    tracefmt = "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.19041.0\\x64\\tracefmt.exe"    
    commandline = "{} {} -nosummary -o tmftrace.txt".format(tracefmt, os.path.join(folder, etl_trace))
    subprocess.run(commandline)

def translateError(hr):
    err =  '"C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.19041.0\\x64\\err.exe"'  
    commandline = "{} {}".format(err, hr)
    result = (subprocess.run(commandline, capture_output=True, text=True)).stdout
    errs = []  

    if '.h' in result:		
        result = result.split("\n", -1)
        for line in result:
            if ".h" in line:
                line = line.rstrip()
                while line[-1] != ' ':
                    line = line.rstrip(line[-1])
                line = line.strip()
                errs.append(line)
 
    return errs

def parseLine(line):
    isError =''    
    separators = [" ", "{", "}", "wilActivity", "'", '"']
    for separator in separators:
        line = line.replace(separator, "")

    line = line.split(",", -1)
    time, tid, hr, pid, activity, event = '', '', '', '', '', ''

    for item in line:
        data = item.split(":", 1)
        
        if not data[0]:
            data.remove(data[0])
        else:
            data[0] = str(data[0]).lower()

        if data[0] == "time":
            time = data[1].replace("T", " ")
        elif data[0] == "tid":
            tid = data[1]
        elif data[0] == "pid":
            pid = data[1]
        elif data[0] == "activity":
            activity = data[1]
        elif data[0] == "event":
            event = data[1]
        elif "hresult" in data[0]:
            hr = (data[0].split(":"))[1]

    if hr:
        errorTranslation = ''
        if hr != "0":
            errs   = translateError(hr)
            if not errs:
                errorTranslation = "Unknown Error"
            else:
                for err in errs:
                    errorTranslation += ' {} |'.format(err)
                    

            fString = f"ERROR {hr} | {time} | Thread ID: {tid} | Process ID: {pid} | Activity: {activity} | Event: {event}"
            isError = '{} : {}'.format(hr, errorTranslation)
        else:
            fString = f"SUCCESS | {time} | Thread ID: {tid} | Process ID: {pid} | Activity: {activity} | Event: {event}"
    else:
        fString = False

    return  isError, fString


def parseTrace(folder, etl_trace):
    decodeEtlTrace(folder, etl_trace)
    etl_report = []
    errors     = []
    with open ("tmftrace.txt", 'r+') as t:
        trace = [line.rstrip() for line in t]      
        for line in trace:
            if "AssignedAccess" in line:
                isError, line = parseLine(line)
                if line:
                    etl_report.append(line)
                    if isError:
                        errors.append(isError)

    os.remove("tmftrace.txt")
    return etl_report, errors