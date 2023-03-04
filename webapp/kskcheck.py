from flask import Flask, flash, request, redirect, render_template, send_from_directory, url_for, send_file
from kskparser import showReport
from dirs import *
from upload import *
import os


app=Flask(__name__)

app.secret_key = "secret key"
app.config['MAX_CONTENT_LENGTH'] = 512 * 1024 * 1024


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
        uploadDirCheck()
        app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

        validationResult = fileValidation()

        if len(validationResult) == 1:
            flash(validationResult[0], 'error')
            return redirect(request.url)
        else:
            files_to_save, etl_trace = validationResult
            for file in files_to_save:
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename.rsplit("/")[-1] ))

            report_id   = reportIdCreate()
            caseNo      = caseNumberValidation()

            if not caseNo:
                flash(FLASH_INVALIDCASENO, 'error')
                return redirect(request.url)
            
            report_file = showReport(report_id, etl_trace)                             
            with open(REPORT_HISTORY, 'a') as f:
                f.write("{} - {}\n".format(report_id, caseNo))
                
            uploadCleanup()            
            return redirect(url_for('download_report', report_file=report_file))

if __name__ == "__main__":    
    dirCheck()
    app.run(host='127.0.0.1',port=5000,debug=False,threaded=True)     