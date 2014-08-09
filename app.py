from flask import Flask, render_template, request, redirect, session, jsonify
import jinja2
import os
from bson.objectid import ObjectId
from pymongo import *
from utils import *
import re
# from secret import *
import random

app = Flask(__name__)

app.secret_key = os.environ['SECRET_KEY']
# app.secret_key = SECRET_KEY

client = MongoClient(os.environ['MONGO_THING'])
# client = MongoClient(MONGO_THING)

db = client.get_default_database()
users = db.users
classes = db.classes
cache = db.cache


COURSE_REGEX = "^[\w\-\. ]+$"
MOD_TIMES = ['8:13-8:28', '8:31-8:46', '8:49-9:04', '9:07-9:22', '9:25-9:40', '9:43-9:58', '10:01-10:16', '10:19-10:34', '10:37-10:52', '10:55-11:10', '11:13-11:28', '11:31-11:46', '11:49-12:04', '12:07-12:22', '12:25-12:40', '12:43-12:58', '1:01-1:16', '1:19-1:34', '1:37-1:52', '1:55-2:10', '2:13-2:28', '2:31-2:46', '2:49-3:04', '3:07-3:22', '3:25-3:38', '3:41-3:54', '3:57-4:10']

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

def get_class(class_id):
	return classes.find_one({'_id' : class_id})

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

def get_cached_courses():
	return str(cache.find_one({'name':'classes'})['classes']).replace("u'", "'")

def is_admin():
	return logged_in() and (session.get('username') == 'jarzon' or session.get('username') == 'parmod')

def split_into_mods(day, color=True):
	mods = dict((key, None) for key in range(1,28))
	for c in day:
		start = c['time'][0]
		end = c['time'][1]
		for mod in range(start, end + 1):
			mods[mod] = {}
			mods[mod]['name'] = c['class_name']
			mods[mod]['students_enrolled_ids'] = c['students_enrolled_ids']
			mods[mod]['students_enrolled_names'] = ', '.join(c['students_enrolled_names'])
			if color:
				mods[mod]['color'] = c['color']
	return mods

def split_courses_into_days(courses):
	all_courses_list = courses.values()
	days = {"monday" : [], "tuesday" : [], "wednesday" : [], "thursday" : [], "friday" : []}
	# colors = ['26, 188, 156', '46, 204, 113', '52, 152, 219', '155, 89, 182', '52, 73, 94', '241, 196, 15', '230, 126, 34', '231, 76, 60', '127, 140, 141', '192, 57, 43', '211, 84, 0']
	# colors = ['26, 188, 156', '41, 128, 185', '142, 68, 173', '192, 57, 43', '52, 73, 94']
	colors = ['243, 236, 12', '252, 39, 18', '198, 50, 253', '254, 209, 100', '134, 205, 77', '128, 128, 128', '100, 255, 240', '253, 164, 160', '255, 255, 255']
	colored_schedule = True
	for c in all_courses_list:
		current_color = ""
		if len(colors) <= 0:
			colored_schedule = False
		else:
			current_color = colors.pop(random.randint(0, len(colors) - 1))
		for day in c['time'].keys():
			c_copy = dict(c)
			c_copy['time'] = c['time'][day]
			days[day].append(c_copy)
			c_copy['color'] = current_color
	return [split_into_mods(days["monday"], colored_schedule),
			split_into_mods(days["tuesday"], colored_schedule),
			split_into_mods(days["wednesday"], colored_schedule),
			split_into_mods(days["thursday"], colored_schedule),
			split_into_mods(days["friday"], colored_schedule)]

@app.route('/')
def index():
	if logged_in():
		courses = get_courses()
		if courses == {}:
			return redirect('/add')
		return render_template('my_classes.html', signed_in=True, name=session['name'].title(),classes=courses)
	return render_template("index.html", page="index")

@app.route('/pretty')
def pretty_schedule():
	if logged_in():
		courses = get_courses()
		if courses == {}:
			return redirect('/add')
		monday, tuesday, wednesday, thursday, friday = split_courses_into_days(courses)
		return render_template('pretty.html', signed_in=True, name=session['name'].title(), monday=monday, tuesday=tuesday, wednesday=wednesday, thursday=thursday, friday=friday, mod_times=MOD_TIMES)
	return redirect('/')

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
		course_list = get_cached_courses()
		while not request.form.get('class_name' + str(i)) is None:
			class_name = request.form.get('class_name' + str(i)).strip()
			if re.match(COURSE_REGEX, class_name) is None:
				return render_template('add.html', page="add", signed_in=True, name=session['name'].title(), error="Invalid class name", course_list=course_list)
			time = {}
			for day in days_of_the_week:
				start = request.form.get(day + "_mods_start" + str(i))
				if start == "":
					continue
				end = request.form.get(day + "_mods_end" + str(i))
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
				course_list = get_cached_courses()
				return render_template('add.html', page="add", signed_in=True, name=session['name'].title(), error="No mods found", course_list=course_list)
			time_to_search = {}
			if time.get('monday'):
				time_to_search['time.monday'] = {"$in" : time.get('monday')}
			if time.get('tuesday'):
				time_to_search['time.tuesday'] = {"$in" : time.get('tuesday')}
			if time.get('wednesday'):
				time_to_search['time.wednesday'] = {"$in" : time.get('wednesday')}
			if time.get('thursday'):
				time_to_search['time.thursday'] = {"$in" : time.get('thursday')}
			if time.get('friday'):
				time_to_search['time.friday'] = {"$in" : time.get('friday')}
			to_search = {"class_name_lower" : c['class_name_lower']}
			to_search.update(time_to_search)
			results = classes.find_one(to_search)
			if results is None:
				print "insertion"
				r = classes.insert(c)
				if not r in user['classes']:
					user['classes'].append(r)
				cache_data = cache.find_one({'name':'classes'})
				course_list = cache_data['classes']
				lower_course_list = map(lambda x:x.lower(),course_list)
				if not c['class_name'].strip().lower() in lower_course_list:
					course_list.append(c['class_name'].strip())
					cache_data['classes'] = course_list
					cache.update({'name':'classes'},cache_data)
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
		course_list = get_cached_courses()
		return render_template('add.html', page="add", signed_in=True, name=session['name'].title(), course_list=course_list)
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
			if len(exploded[1]) > 0:
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
		users.update({'_id':user.get('_id')},user)
		return redirect('/')
	if not(logged_in()):
		return redirect('/signin')
	return render_template('account.html',signed_in=True, name=session['name'].title())
@app.route('/account/delete', methods=['POST'])
def account_delete():
	if request.method == 'POST':
		if not logged_in():
			return redirect('/signin')
		password = request.form.get('password')
		if password is None:
			return render_template('account.html', signed_in=True, name=session['name'].title(), error="Incorrect password")
		username = session['username']
		user = get_user(username)
		if user is None:
			return redirect('/signin')
		if valid_pw(username,password,user.get('password')):
			for c in user['classes']:
				course = classes.find_one({"_id" : c})
				index = course['students_enrolled_ids'].index(user.get("_id"))
				course['students_enrolled_ids'].pop(index)
				if len(course['students_enrolled_ids']) == 0:
					classes.remove({"_id":class_id})
				course['students_enrolled_names'].pop(index)
				classes.update({"_id" : c}, course)
				classes.update({'_id':c},course)
			users.remove({'_id':user.get('_id')})
			session_logout()
			return redirect('/')
		else:
			return render_template('account.html', signed_in=True, name=session['name'].title(), error="Incorrect password")

@app.route('/classes.json')
def class_json():
	# return jsonify(classes=cache.get('classes'))
	return get_cached_courses()
@app.route('/find', methods=['GET','POST'])
def find_classes():
	if request.method == 'POST':
		class_name = request.form.get('class_name')
		matches = classes.find({'class_name':class_name})
		course_list = get_cached_courses()
		return render_template('find_classes.html', signed_in=True,page="add", name=session['name'].title(), course_list=course_list, found_classes=matches)
	if logged_in():
		course_list = get_cached_courses()
		return render_template('find_classes.html', signed_in=True,page="add", name=session['name'].title(), course_list=course_list)
	return redirect('/signin')

@app.errorhandler(404)
def broken(error):
	return render_template('404.html'), 404

@app.route('/404')
def forohfor():
	return render_template('404.html'), 404

@app.errorhandler(500)
def broken(error):
	return render_template('500.html'), 500

@app.route('/500')
def fivehundred():
	return render_template('500.html'), 500

@app.route('/admin')
def admin_page():
	if is_admin():
		return render_template('admin.html')
	return redirect('/')

@app.route('/delete_class_admin', methods=['GET','POST'])
def delete_class_admin():
	if request.method == 'POST' and is_admin():
		class_id = request.form.get('delete_class_id')
		to_delete = get_class(ObjectId(class_id))
		if to_delete is None:
			return render_template('admin.html', error="No class found.")
		stu_ids = to_delete.get('students_enrolled_ids')
		for student in stu_ids:
			user = get_user(student)
			user['classes'].pop(to_delete.get("_id"))
			users.update({"_id" : student}, user)
		name = to_delete.get('class_name')
		classes.remove({"_id" : ObjectId(class_id)})
		return render_template('admin.html', error="Deleted " + name)
	else:
		return redirect('/')

def merge_classes():
	return False
	all_courses_names = cache.find_one({'name':'classes'})['classes']
	for course in all_courses_names:
		results = classes.find({"class_name_lower" : course.lower()})
		results_retrieved = []
		for r in results:
			results_retrieved.append(r)
		groups = group_classes(results_retrieved)
		### merge groups

def group_classes(data):
	results_retrieved = list(data)
	groups = []
	while len(results_retrieved) > 0:
		first_element = results_retrieved[0]
		current_group = [first_element]
		indices_to_remove = [0]
		current_index = 0
		for b in results_retrieved:
			current_index += 1
			if first_element.get("_id") == b.get("_id"):
				continue
			if first_element.get("time") == b.get("time"):
				current_group.append(b)
				indices_to_remove.append(current_index - 1)
		groups.append(current_group)
		delta = 0
		indices_to_remove.sort()
		print indices_to_remove, len(results_retrieved)
		for index in indices_to_remove:
			print index - delta
			results_retrieved.pop(index - delta)
			delta += 1
	return groups

if __name__ == '__main__':
	port = int(os.environ.get('PORT', 8000))
	app.run(host='0.0.0.0', port=port,debug=True)