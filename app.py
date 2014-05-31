from flask import Flask, render_template, request, redirect
import jinja2
import os
from bson.objectid import ObjectId
from pymongo import *
from utils import *

app = Flask(__name__)

client = MongoClient("mongodb://admin:monkeY5nexus@kahana.mongohq.com:10051/classmatch")
db = client.get_default_database()
users = db.users
classes = db.classes

@app.route('/')
def hello():
	return render_template("index.html", page="index")
@app.route('/signin', methods=['GET','POST'])
def sign_in():
	if request.method == 'POST':
		return redirect('/')
	return render_template("signin.html")
@app.route('/signup', methods=['GET','POST'])
def sign_up():
	if request.method == 'POST':
		first_name = request.form.get('first_name')
		last_name = request.form.get('last_name')
		username = request.form.get('username')
		password = request.form.get('password')
		password_confirm = request.form.get('password_confirm')
		if not(first_name) or not(last_name) or not(username) or not(password) or not(password_confirm):
			return render_template('signup.html', error="Cannot leave any field blank!")
		if not(valid_username(username)):
			return render_template('signup.html', error="Enter a valid username")
		if not(valid_password(password)):
			return render_template('signup.html', error="Enter a valid password")
		if password != password_confirm:
			return render_template('signup.html', error="Passwords must match")
		password = make_pw_hash(username,password)
		user_id = users.insert({"username": username,"password": password,"first_name":first_name.lower(),"last_name":last_name.lower(),'classes':[]})
		return redirect('/user/' +user_id)
	return render_template("signup.html")
@app.route('/user/<id>')
def get_user_info(id):
	user = users.find({'_id':ObjectId(id)})[0]
	return render_template('user_info.html', user=user)
if __name__ == '__main__':
	port = int(os.environ.get('PORT', 8000))
	app.run(host='0.0.0.0', port=port,debug=True)