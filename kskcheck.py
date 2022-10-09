from flask import Flask, flash, request, redirect, render_template, send_from_directory, url_for, send_file
from datetime import datetime
from kskparser import showReport
import os, glob


app=Flask(__name__)

app.secret_key = "secret key"
app.config['MAX_CONTENT_LENGTH'] = 512 * 1024 * 1024
DIRECTORY_TO_SERVE_PATH = './kaDownload'
REPORT_DIR = './reports'

@app.route('/')
def upload_form():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/documentation')
def documentation():
    return render_template('kadoc.html')

@app.route('/download')
def download():
    return send_from_directory(DIRECTORY_TO_SERVE_PATH, 'kioskAssistant.zip')

@app.route('/download_report/<report_file>')
def download_report(report_file):
    return send_file(os.path.join(REPORT_DIR, report_file), as_attachment=True)

@app.route('/kioskmdm')
def kioskmdm():
    return render_template('kioskmdm.html')

@app.route('/', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        dt_string = datetime.now().strftime("%Y.%m.%d__%H.%M.%S.%f")
        caseNo = request.form['caseno']
        if caseNo and (len(caseNo) != 8 and len(caseNo) != 16):
            flash('Invalid case number')
            return redirect(request.url)
        elif not caseNo:
            caseNo = "Case No. not specified"

        files_to_save = []
        etl_trace     = ""

        necessary_files = ['AssignedAccess_Reg', 'AssignedAccessCsp_Reg', 'AssignedAccessManagerSvc_Reg', 'ConfigManager_AssignedAccess_Reg', 'Get-AppxPackage-AllUsers', 'Get-AssignedAccess', 'ShellLauncher_Reg', 'Get-StartApps', 'Winlogon_Reg']
        files = request.files.getlist('files[]')
        if len(files) > 1:
            for file in files:
                fn = file.filename.rsplit("/")[-1]
                if '.etl' in fn:
                    etl_trace = fn
                    files_to_save.append(file)
                else:
                    for necessary_file in necessary_files:
                        if necessary_file + '.txt' == fn:
                            necessary_files.remove(necessary_file)
                            files_to_save.append(file)

            if necessary_files:
                mfCount = 0
                flash("Not all necessary files were selected. Make sure the following file(s) exist in the folder:\n")
                for file in necessary_files:
                    mfCount += 1
                    flash(f"{mfCount}) {file}.txt\n")
                return redirect(request.url)

            report_id = ( 'report_' + dt_string )
            path = os.getcwd()
            UPLOAD_FOLDER = os.path.join(path, 'uploads', report_id)  
            os.mkdir(UPLOAD_FOLDER)
            app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

            for file in files_to_save:
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename.rsplit("/")[-1] ))

            report_file = showReport(UPLOAD_FOLDER, report_id, etl_trace)

            rm_files = glob.glob(os.path.join(UPLOAD_FOLDER, '*'), recursive=True)
            for f in rm_files:
                os.remove(f)
            os.rmdir(UPLOAD_FOLDER)            
            
            with open('report_history.txt', 'a') as f:
                f.write("{} - {}\n".format(dt_string, caseNo))

            return redirect(url_for('download_report', report_file=report_file))
        else:
            flash('No folder selected')
            return redirect(request.url)



if __name__ == "__main__":
    app.run(host='127.0.0.1',port=5000,debug=False,threaded=True)    