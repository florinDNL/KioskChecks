import subprocess, os


def decodeEtlTrace(folder, etl_trace):
    tracefmt = "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.19041.0\\x64\\tracefmt.exe"    
    commandline = "{} {} -nosummary -o tmftrace.txt".format(tracefmt, os.path.join(folder, etl_trace))
    subprocess.run(commandline)
    
def parseLine(line):
    separators = [" ", "{", "}", "wilActivity", "'", '"']
    for separator in separators:
        line = line.replace(separator, "")

    line = line.split(",", -1)
    time, tid, hr, pid, activity, event = '', '', '', '', '', ''

    for item in line:
        data = item.split(":", 1)
        if not data[0]:
            data.remove(data[0])
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
        elif data[0] == "hresult":
            hr = data[1]

        
    if hr and hr != "0":
        fString = f"!!ERROR!! HRESULT: {hr} | {time} | Thread ID: {tid} | Process ID: {pid} | Activity: {activity} | Event: {event}"
    else:
        fString = f"SUCCESS | {time} | Thread ID: {tid} | Process ID: {pid} | Activity: {activity} | Event: {event}"

    return fString


def parseTrace(folder, etl_trace):
    decodeEtlTrace(folder, etl_trace)
    etl_report = []
    with open ("tmftrace.txt", 'r+') as t:
        trace = [line.rstrip() for line in t]      
        for line in trace:
            if "AssignedAccess" in line:
                line = parseLine(line)
                etl_report.append(line)

    os.remove("tmftrace.txt")
    return etl_report