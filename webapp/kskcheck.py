from flask import Flask, flash, request, redirect, render_template, url_for, send_file
from regparser import writeReport
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
    return redirect(KA_REL_URL)

@app.route('/downloadscript')
def downloadScript():
    return send_file(KIOSKMDM, as_attachment=True)

@app.route('/download_report/<report_file>')
def download_report(report_file):
    return send_file(os.path.join(REPORT_DIR, report_file), as_attachment=True)

@app.route('/kioskmdm')
def kioskmdm():
    return render_template('kioskmdm.html')

@app.route('/', methods=['POST'])
def upload_file():    
    if request.method == 'POST':

        caseNo = caseNumberValidation(request.form['caseno'])
        if not caseNo:
            flash(FLASH_INVALIDCASENO, 'error')
            return redirect(request.url)        
        
        validationResult = fileValidation(request.files.getlist('files[]'), request.files.get('file'))
        if len(validationResult) == 1:
            flash(validationResult[0], 'error')
            return redirect(request.url)

        uploadDirCheck()
        app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER        
    
        files_to_save, etl_trace = validationResult
        for file in files_to_save:
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename.rsplit("/")[-1] ))

        report_id   = reportIdCreate()

        try:
            report_file = writeReport(report_id, etl_trace)
        except:
               flash(FLASH_INTERNALERR, 'error')    
               return redirect(request.url)      
                       
        with open(REPORT_HISTORY, 'a') as f:
            f.write("{} - {}\n".format(report_id, caseNo))
            
        uploadCleanup()           

        return redirect(url_for('download_report', report_file=report_file))


if __name__ == "__main__":    
    dirCheck()
    app.run(host='0.0.0.0',port=5000,debug=False,threaded=True)     