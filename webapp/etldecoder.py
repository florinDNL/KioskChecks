import subprocess, os
from dirs import UTIL_DIR, UPLOAD_FOLDER


def decodeEtlTrace(etl_trace):
    tracefmt = os.path.join(UTIL_DIR, 'tracefmt.exe')
    output   = os.path.join(UPLOAD_FOLDER, 'fmttrace.txt')   
    commandline = '"{}" "{}" -nosummary -o "{}"'.format(tracefmt, os.path.join(UPLOAD_FOLDER, etl_trace), output)
    subprocess.run(commandline)


def translateError(hr):
    err =  os.path.join(UTIL_DIR, 'err.exe')  
    commandline = "{} {}".format(err, hr)
    print(commandline)
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
    separators = [" ", "{", "}", "wilActivity", "'", '"']
    fString, isError, time, tid, hr, pid, activity, event = '', '', '', '', '', '', '', ''
    for separator in separators:
        line = line.replace(separator, "")

    line = line.split(",", -1)    

    for item in line:
        data = item.split(":", 1)
        
        if not data[0]:
            data.remove(data[0])
        else:
            data_string = str(data[0]).lower()

        if data_string == "time":
            time = data[1].replace("T", " ")
        elif data_string == "tid":
            tid = data[1]
        elif data_string == "pid":
            pid = data[1]
        elif data_string == "activity":
            activity = data[1]
        elif data_string == "event":
            event = data[1]
        elif "hresult" in data_string:
            hr = (data_string.split(":"))[1]

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

    return  isError, fString


def parseTrace(etl_trace):
    decodeEtlTrace(etl_trace)
    etl_report = []
    errors     = []
    output = os.path.join(UPLOAD_FOLDER, 'fmttrace.txt')
    with open (output, 'r+') as t:
        trace = [line.rstrip() for line in t]      
        for line in trace:
            if "AssignedAccess" in line:
                isError, line = parseLine(line)
                if line:
                    etl_report.append(line)
                    if isError:
                        errors.append(isError)

    return etl_report, errors
