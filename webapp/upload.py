from flask import request
from datetime import datetime
import os
from dirs import *
from string_const import *

def fileValidation():  
    necessary_files = fileList()
    files_to_save = []
    result = []
    files = request.files.getlist('files[]')    
    etl_tracefile = request.files.get('file')
    etl_trace = ""
  
    if etl_tracefile:
        files_to_save.append(etl_tracefile)
        etl_trace = os.path.join(UPLOAD_FOLDER, etl_tracefile.filename)
  
    if len(files) > 1:
            for file in files:
                fn = file.filename.rsplit("/")[-1]            
                for necessary_file in necessary_files:
                    if necessary_file + '.txt' == fn:
                        necessary_files.remove(necessary_file)
                        files_to_save.append(file)

            if necessary_files:                
                message = FLASH_MISSINGFILES
                for file in necessary_files:
                    message += FLASH_MISSINGFILESLIST.format(file)           
                result.append(message) 
            else:
                result.append(files_to_save)
                result.append(etl_trace)       
    else:
        message = FLASH_NOFOLDER        
        result.append(message)

    return result


def caseNumberValidation():    
    caseNo = request.form['caseno']
    if caseNo and (len(caseNo) != 8 and len(caseNo) != 16):        
        caseNo = False
    elif not caseNo:
        caseNo = "Unspecified Case No."
    
    return caseNo
    

def reportIdCreate():
    dt_string = datetime.now().strftime("%Y.%m.%d__%H.%M.%S.%f")
    report_id = ( 'report_' + dt_string )

    return report_id