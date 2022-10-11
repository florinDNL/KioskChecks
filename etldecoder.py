import subprocess, os


def decodeEtlTrace(folder, etl_trace):
    tracefmt = "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.19041.0\\x64\\tracefmt.exe"    
    commandline = "{} {} -nosummary -o tmftrace.txt".format(tracefmt, os.path.join(folder, etl_trace))
    subprocess.run(commandline)
    
def parseLine(line):
    separator1 = "::"
    time = line.split(separator1, 1)
    return time

def parseTrace(folder, etl_trace):
    decodeEtlTrace(folder, etl_trace)
    etl_report = []
    with open ("tmftrace.txt", 'r+') as t:
        trace = [line.rstrip() for line in t]      
        for line in trace:
            if  "AssignedAccess" in line and "hresult" in line and '"hresult":0' not in line:
                etl_report.append(line) 

        if not t.readlines():
            etl_report.append("Non-zero HRESULT events not found. Dumping all AssignedAccess events, error might not be among them.\n\n")
            for line in trace:
                if "AssignedAccess" in line:
                    line = parseLine(line)
                    etl_report.append(line)

    os.remove("tmftrace.txt")
    return etl_report