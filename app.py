from flask import Flask, render_template, request, redirect, session, jsonify
import jinja2
import os
from bson.objectid import ObjectId
from pymongo import *
from utils import *
# from secret import *

app = Flask(__name__)

cache = {}
app.secret_key = os.environ['SECRET_KEY']

client = MongoClient(os.environ['MONGO_THING'])
db = client.get_default_database()
users = db.users
classes = db.classes
old_courses = ["Data Structures", "AP Psychology ", "Adv Analysis II", "Adv Analysis I", "Math Analysis II", "Math Analysis I", "Gateway Seminar", "AP Calculus AB", "Calculus I", "PE", "Adv Biology", "Biology Honors", "IB Espanol IV SL", "IB Espanol IV HL", "IB Espanol V SL", "IB Espanol V HL", "Espanol III", "Espanol II", "Espanol I/II", "World Lit I", "World Lit II", "IB World Lit I HL", "IB World Lit II HL", "IB Literature_Language I HL", "IB Literature_Language II HL", "American Lit I", "American Lit II", "Francais II", "Francais III", "IB Francais IV SL", "IB Francais IV HL", "World History", "US History I", "US History II", "IB Hist of Amer I HL", "IB Hist of Amer II HL", "Theatre History II", "AP Art History", "AP Comp Sci A", "Hotel Mgmt_Cul Theory", "Theory of Knowledge", "Elec Music Synthesis", "Music and Society", "AP Music Theory in Digital Age", "Culinary", "Prin of Eng_Mat Sci", "AP Language and English Composition", "Intro to Engineering Design II", "Intro to Engineering Design I", "Interm Electrical Eng", "Discrete II", "Discrete II", "AP Chemistry", "Adv Chemistry", "Intermediate Chemistry", "Java Programming", "Constitutional Law", "Mandarin I", "Mandarin II", "Mandarin III", "Mandarin 3", "IED 2", "IB Economics HL", "AP Micro Economics", "Acting II", "Police and Corrections", "Manufac Process CIM", "Robotics", "Advanced Math Topics", "Adv Business Topics 1", "Adv Business Topics 2", "Dance I", "Dance II", "Design and Production Tech", "Biotech Lab", "Driver's Education", "Publishing", "Entrep_Adv Cul Arts", "Physical Education", "IB Physics", "Intro to Physics", "Intermediate Physics", "Advanced Physics", "AP Physics C", "Cell Physiology"]

if not(cache.get('classes')):
	cache['classes'] = old_courses

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

def get_user(username):
	user = users.find_one({'username' : username})
	if user is None:
		session_logout()
	return user

def get_courses():
	username = session['username']
	user = get_user(username)
	courses = {}
	if not user['classes']:
		return {}
	for c in user['classes']:
		one_class = classes.find_one({'_id': c})
		# courses[one_class['class_name']] = one_class['students_enrolled_names']
		courses[c] = one_class
	return courses

@app.route('/')
def index():
	if logged_in():
		courses = get_courses()
		if courses == {}:
			return redirect('/add')
		return render_template('my_classes.html', signed_in=True, name=session['name'].title(),classes=courses)
	return render_template("index.html", page="index")

@app.route('/about')
def about():
	if logged_in():
		return render_template('about.html', signed_in=True, name=session['name'].title(), page='about')
	return render_template('about.html', page='about')

@app.route('/delete_class/<class_id>')
def delete_class(class_id):
	if logged_in():
		class_id = ObjectId(class_id)
		user = get_user(session.get('username'))
		if user is None:
			return redirect('/signin')
		course = classes.find_one({"_id" : class_id})
		if course is None:
			return redirect('/classes')
		index = course['students_enrolled_ids'].index(user.get("_id")) #will throw ValueError if problem, we should make error page
		course['students_enrolled_ids'].pop(index)
		if len(course['students_enrolled_ids']) == 0:
			classes.remove({"_id":class_id})
		course['students_enrolled_names'].pop(index)
		classes.update({"_id" : class_id}, course)
		user['classes'].pop(user['classes'].index(class_id))
		users.update({"_id" : user.get("_id")}, user)
		return redirect('/classes')
	return redirect('/login')

@app.route('/add', methods=['GET', 'POST'])
def add_class():
	if request.method == 'POST':
		if not logged_in():
			return redirect('/signin')
		days_of_the_week = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday']
		i = 1
		courses = []
		user = get_user(session['username'])
		if user is None:
			return redirect('/signin')
		if user.get("last_name") is None:
			name = user.get("first_name")
		else:
			name = user.get("first_name") + " " + user.get("last_name")
		while not request.form.get('class_name' + str(i)) is None:
			class_name = request.form.get('class_name' + str(i))
			time = {}
			for day in days_of_the_week:
				start = request.form.get(day + "_mods_start" + str(i))
				if start == "":
					continue
				end = request.form.get(day + "_mods_end" + str(i))
				if not cache.get('classes'):
					cache.set('classes',old_courses)
				course_list = str(cache.get('classes'))
				try:
					start = int(start)
					end = int(end)
				except ValueError:
					return render_template('add.html', page="add", signed_in=True, name=session['name'].title(), error="Mods must be integers", course_list=course_list)
				if start > 27  or start < 1 or end > 27 or end < 1:
					return render_template('add.html', page="add", signed_in=True, name=session['name'].title(), error="Mods must be a number from 1 to 27", course_list=course_list)
				time[day] = [start, end]
			courses.append({
				"class_name" : class_name,
				"class_name_lower" : class_name.lower(),
				"time" : time,
				"students_enrolled_names" : [name], #add teacher when we get those
				"students_enrolled_ids" : [user.get("_id")]
				})
			i += 1
		for c in courses:
			results = None
			if time == {}:
				if not cache.get('classes'):
					cache.set('classes',old_courses)
				course_list = str(cache.get('classes'))
				return render_template('add.html', page="add", signed_in=True, name=session['name'].title(), error="No mods found", course_list=course_list)
			results = classes.find_one({"class_name_lower" : c['class_name_lower'], "time" : c['time']})
			if results is None:
				r = classes.insert(c)
				if not r in user['classes']:
					user['classes'].append(r)
				cached_classes = cache.get('classes')
				if not c['class_name'] in cached_classes:
					cache['classes'] = cached_classes.append(r)
				continue
			if not name in results['students_enrolled_names']:
				results['students_enrolled_names'].append(name)
				results['students_enrolled_ids'].append(user.get("_id"))
			r = classes.update({"_id" : results.get("_id")}, results)
			if not r in user['classes']:
				user['classes'].append(results.get("_id"))
		x = users.update({"_id" : user.get("_id")}, user)
		return redirect('/')
	if logged_in():
		user = get_user(session['username'])
		if user is None:
			return redirect('/signin')
		user_classes = []
		for course in user.get('classes'):
			user_classes.append(classes.find_one({"_id" : course}))
		if not cache.get('classes'):
			cache.set('classes',old_courses)
		course_list = str(cache.get('classes'))
		return render_template('add.html', page="add", signed_in=True, name=session['name'].title(), courses=cache.get("classes"), course_list=course_list)
	return redirect('/signin')

@app.route('/signin', methods=['GET','POST'])
def sign_in():
	if request.method == 'POST':
		username = request.form.get('username').lower()
		if '@bergen.org' in username:
			username = username.split("@bergen.org")[0]
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
		if '@bergen.org' in username:
			username = username.split("@bergen.org")[0]
		password = request.form.get('password')
		password_confirm = request.form.get('password_confirm')
		variables = {"first_name" : first_name, "last_name" : last_name, "username" : username}
		if not username:
			return render_template('signup.html', variables=variables, username_error="No username found.")
		if not first_name:
			return render_template('signup.html', variables=variables, first_name_error="No first name found.")
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
		return redirect('/add')
	if logged_in():
		return redirect('/')
	return render_template("signup.html", variables=None)
@app.route('/user/<id>')
def get_user_info(id):
	if not(logged_in()):
		return redirect('/signin')
	user = users.find({'_id':ObjectId(id)})[0]
	last_name = user.get('last_name')
	name = user['first_name']
	if last_name:
		name += ' ' + last_name
	email = user['username'] +'@bergen.org'
	courses=[]
	for c in user['classes']:
		courses.append(classes.find_one({'_id':c})['class_name'])
	return render_template('user_info.html', signed_in=True, name=session['name'].title(),classes=courses, user_name=name.title(), email=email)
@app.route('/classes')
def my_classes():
	if logged_in():
		courses = get_courses()
		if courses == {}:
			return redirect('/add')
		return render_template('my_classes.html',signed_in=True, name=session['name'].title(), classes=courses)
	return redirect('/signin')
@app.route('/logout')
def logout():
	session_logout()
	return redirect('/')
@app.route('/account', methods=['GET','POST'])
def account():
	if request.method == 'POST':
		old_password = request.form.get('old_password')
		new_password = request.form.get('new_password')
		confirm_password = request.form.get('confirm_password')
		if not(old_password) or not(new_password) or not(confirm_password):
			return render_template('account.html',signed_in=True, name=session['name'].title(), error="Cannot leave any field blank!")
		if new_password != confirm_password:
			return render_template('account.html',signed_in=True, name=session['name'].title(), error="Passwords must match")
		username = session['username']
		user = get_user(username)
		if user is None:
			return redirect('/signin')
		if not(valid_pw(username,old_password,user.get('password'))):
			return render_template('account.html',signed_in=True, name=session['name'].title(), error="Incorrect password")
		user['password'] = make_pw_hash(username,new_password)
		users.update({'_id':user.get('id')},user)
		return redirect('/')
	if not(logged_in()):
		return redirect('/signin')
	return render_template('account.html',signed_in=True, name=session['name'].title())
@app.route('/account/delete', methods=['POST'])
def account_delete():
	if request.method == 'POST':
		password = request.form.get('password')
		username = session['username']
		user = get_user(username)
		if user is None:
			return redirect('/signin')
		if valid_pw(username,password,user.get('password')):
			for c in user['classes']:
				course = classes.find_one({"_id" : c})
				for ids in course['students_enrolled_ids']:
					if ids == user['id']:
						course['students_enrolled_ids'].remove(ids)
				for names in course['students_enrolled_ids']:
					full_name = user['first_name'] + ' ' + user['last_name']
					if names == full_name:
						course['students_enrolled_ids'].remove(names)
				classes.update({'_id':c},course)
			users.remove({'_id':user.get('id')})
			session_logout()
			return redirect('/')
@app.route('/classes.json')
def class_json():
	# return jsonify(classes=cache.get('classes'))
	if not cache.get('classes'):
		cache.set('classes',old_courses)
	return str(cache.get('classes'))
if __name__ == '__main__':
	port = int(os.environ.get('PORT', 8000))
	app.run(host='0.0.0.0', port=port,debug=True)