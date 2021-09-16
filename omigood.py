from flask import Flask, render_template
import threading

app = Flask(__name__)

@app.route('/')
def index():

    return render_template('index.html')

threading.Thread(target=app.run, kwargs={
                 "port": 3000, "host": "0.0.0.0"}).start()
