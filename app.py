from flask import Flask, render_template, request, redirect, session
import jinja2
import os
from bson.objectid import ObjectId
from pymongo import *
from utils import *

app = Flask(__name__)
app.secret_key = "01b9db9bcfbc3c0ab01cb7231e0e2f2a42c9fc20d39d58791655a7f0c3e584a1"

client = MongoClient("mongodb://admin:monkeY5nexus@kahana.mongohq.com:10051/classmatch")
db = client.get_default_database()
users = db.users
classes = db.classes

def session_login(username, first_name):
	session['username'] = username
	session['name'] = first_name

def session_logout():
	session.pop('username', None)
	session.pop('name', None)

def logged_in():
	if session.get('username') is None:
		session_logout()
		return False
	return True

@app.route('/')
def hello():
	if logged_in():
		return render_template('classes.html', signed_in=True, name= session['name'].title())
	return render_template("index.html", page="index")
@app.route('/signin', methods=['GET','POST'])
def sign_in():
	if request.method == 'POST':
		username = request.form.get('username')
		password = request.form.get('password')
		if not(username):
			return render_template('signin.html', username_error="No username found.")
		if not(password):
			return render_template('signin.html', password_error="No password found.", username=username)
		user = users.find_one({'username':username})
		if user is None:
			return render_template('signin.html', username_error="No account found!", username=username)
		if not(valid_pw(username,password,user.get('password'))):
			return render_template('signin.html', error="Invalid username and password.", username=username)
		session_login(username, user.get('first_name'))
		return redirect('/')
	if logged_in():
		return redirect('/')
	return render_template("signin.html", username="")
@app.route('/signup', methods=['GET','POST'])
def sign_up():
	if request.method == 'POST':
		first_name = request.form.get('first_name')
		last_name = request.form.get('last_name')
		if not last_name and first_name.count(" ") >= 1:
			exploded = first_name.split(" ")
			first_name = exploded[0]
			exploded.pop(0)
			last_name = " ".join(exploded)
		username = request.form.get('username').lower()
		password = request.form.get('password')
		password_confirm = request.form.get('password_confirm')
		variables = {"first_name" : first_name, "last_name" : last_name, "username" : username}
		if not username:
			return render_template('signup.html', variables=variables, username_error="No username found.")
		if not first_name:
			return render_template('signup.html', variables=variables, first_name_error="No first name found.")
		# if not last_name:
		# 	return render_template('signup.html', variables=variables, last_name_error="No last name found.")
		if not password:
			return render_template('signup.html', variables=variables, password_error="No password found.")
		if not password_confirm:
			return render_template('signup.html', variables=variables, password_confirm_error="No re-typed password found.")
		if not valid_username(username):
			return render_template('signup.html', variables=variables, username_error="Enter a valid username")
		if not valid_password(password):
			return render_template('signup.html', variables=variables, password_error="Enter a valid password")
		if password != password_confirm:
			return render_template('signup.html', variables=variables, password_error="Passwords must match", password_confirm_error="Passwords must match")
		result = users.find_one({"username":username})
		if not result is None:
			if valid_pw(username, password, result.get('password')):
				session['username'] = username
				if result.get("last_name") is None:
					session['name'] = result.get('first_name')
				else:
					session['name'] = result.get('first_name') + ' ' + result.get('last_name')
				return redirect('/')
			else:
				return render_template('signup.html', variables=variables, username_error="Username taken.")
		if first_name == first_name.lower() or first_name == first_name.upper():
			first_name = first_name.capitalize()
		if last_name and last_name == last_name.lower() or last_name == last_name.upper():
			last_name = last_name.capitalize()
		password = make_pw_hash(username,password)
		if last_name:
			user_id = users.insert({"username": username,"password": password,"first_name":first_name,"last_name":last_name,"classes":[],"email_verified":False})
		else:
			user_id = users.insert({"username": username,"password": password,"first_name":first_name,"classes":[],"email_verified":False})
		session_login(username, first_name)
		return redirect('/')
	if logged_in():
		return redirect('/')
	return render_template("signup.html", variables=None)
# @app.route('/user/<id>')
# def get_user_info(id):
# 	user = users.find({'_id':ObjectId(id)})[0]
# 	return render_template('user_info.html', user=user)
@app.route('/logout')
def logout():
	session_logout()
	return redirect('/')

if __name__ == '__main__':
	port = int(os.environ.get('PORT', 8000))
	app.run(host='0.0.0.0', port=port,debug=True)