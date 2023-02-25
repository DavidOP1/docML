from flask import Flask, render_template
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from werkzeug.utils import secure_filename
import os
from wtforms.validators import InputRequired
from loop2 import check_malware
import pandas as pd
import numpy as np
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'files_uploaded'

class UploadFileForm(FlaskForm):
    file = FileField("File", validators=[InputRequired()])
    submit = SubmitField("Upload File")


def get_result():
    file=''
    feature= {}
    feature["Call"] = []
    feature["Run"] = []
    feature["Kill"] = []
    feature["Base64"] = []
    feature["PowerShell"] = []
    feature["Hex Strings"] = []
    feature["AutoExec"] = []
    feature["Hex obfuscated"] = []
    feature["Base64 obfuscated"] = []
    feature["Malware"] = []
    feature["VBA Stomping"] = []
    feature["Executable"] = []
    feature["OLE"] = []
    feature["IOC"] = []
    feature["file size"] = []

    for filename in os.listdir('files_uploaded'):
        file=filename
    feature_data = malware.check(file,"check",feature,'./files_uploaded')

    #df = pd.DataFrame(feature_data)
    feature_df = pd.DataFrame(feature_data).to_numpy()
    y_pred = model.predict(feature_df)
    print("predict = " , y_pred[0])
    return y_pred[0]

@app.route('/', methods=['GET',"POST"])
def home_page():
    return "Welcome to DOC and XLS malware check app"

@app.route('/check_file', methods=['GET',"POST"])
def check_file():
    form = UploadFileForm()
    if form.validate_on_submit():
        file = form.file.data # First grab the file
        file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),app.config['UPLOAD_FOLDER'],secure_filename(file.filename))) # Then save the file
        result = get_result()
        file=""
        for filename in os.listdir('files_uploaded'):
            file = filename
        if not result:
            if os.path.exists('files_uploaded/'+file):
              # delete the file
              os.remove('files_uploaded/'+file)
            return render_template('index.html',message="THIS FILE IS SAFE!",form=form)

        elif result==1:
            if os.path.exists('files_uploaded/'+file):
              # delete the file
              os.remove('files_uploaded/'+file)
            return render_template('index.html', message="THIS FILE IS MALWARE!",form=form)
    return render_template('index.html', form=form,message="")

malware = check_malware()
model = malware.run()

if __name__ == '__main__':
    app.run(debug=True)