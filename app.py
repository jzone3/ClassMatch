from flask import Flask, render_template, request, redirect
import jinja2
import os

app = Flask(__name__)

@app.route('/')
def hello():
	return render_template("index.html")
@app.route('/signin', methods=['GET','POST'])
def sign_in():
	return render_template("signin.html")
@app.route('/signup', methods=['GET','POST'])
def sign_up():
	return render_template("signup.html")

if __name__ == '__main__':
	port = int(os.environ.get('PORT', 8000))
	app.run(host='0.0.0.0', port=port,debug=True)