from google.appengine.ext import db
from google.appengine.api import memcache
from google.appengine.api import mail
from google.appengine.api import datastore_errors
import re
import hmac
import hashlib
import datetime
import random
import string
import logging
from secret import *

try:
  # When deployed
  from google.appengine.runtime import OverQuotaError
except ImportError:
  # In the development server
  from google.appengine.runtime.apiproxy_errors import OverQuotaError


EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
PASS_RE = re.compile(r"^.{3,20}$")

class Email_Verification(db.Model):
	email          = db.StringProperty(required = True)
	date_created   = db.DateTimeProperty(auto_now_add = True)

class Users(db.Model):
	email          = db.StringProperty(required = True)
	name           = db.StringProperty(required = True)
	password       = db.StringProperty(required = True)
	date_created   = db.DateTimeProperty(auto_now_add = True)
	email_verified = db.BooleanProperty(required = True)

GET_USER = db.GqlQuery("SELECT * FROM Users WHERE email = :email LIMIT 1")

def remember_me():
	'''Returns expiration time for remember me cookie'''
	expiration = datetime.datetime.now() + datetime.timedelta(days=50)
	return expiration.strftime("%a, %d-%b-%Y %H:%M:%S PST")

def hash_str(string):
	'''Hashes a string for user cookie'''
	return hmac.new(SECRET, str(string), hashlib.sha512).hexdigest()

def salted_hash(password, salt):
	'''Hashes a string for user password'''
	return hashlib.sha256(password + salt).hexdigest()

def make_salt():
	'''Makes random salt for user cookie'''
	return ''.join(random.choice(string.letters) for x in xrange(5))

def unique_email(email):
	'''Checks that an email is not taken already'''
	accounts = (db.GqlQuery("SELECT * FROM Users WHERE email = :email", email = email)).get()
	if accounts is None:
		return True
	return False

def get_user(email, cached = True):
	'''Get User object from email'''
	user = memcache.get('user-'+email)
	if user and cached:
		logging.info('CACHE GET_USER: '+email)
		return user
	else:
		logging.info('DB GET_USER: '+email)
		GET_USER.bind(email = email)
		user = GET_USER.get()

		memcache.set('user-'+email, user)
		logging.info('CACHE set user-'+email)

		return user

def get_name(email, cached=True):
	'''Gets name from db from email'''
	return get_user(email, cached).name

def check_login(email, password):
	"""Checks if login info is correct

	Returns:
		[False, error text]
		OR
		[True, cookie]
	"""

	correct = False

	if email != '' and password != '':		
		accounts = memcache.get('user-'+email)
		if accounts:
			logging.info("CACHE LOGIN check_login(): "+email)
		else:
			logging.info("DB LOGIN check_login(): "+email)
			GET_USER.bind(email = email)
			accounts = GET_USER.get()

			memcache.set('user-'+email, accounts)
			logging.info("CACHE set user-"+email)

		if accounts is None:
			return [False, 'email does not exist']

		(db_password, salt) = (accounts.password).split("|")

		if salted_hash(password, salt) == db_password:
			return [True, '%s=%s|%s;' % (LOGIN_COOKIE_NAME, str(email), str(hash_str(email)))]

	return [False, 'Invalid email or password!']

def change_email(previous_email, new_email):
	"""
	Changes a user's email
	Returns:
		[Success_bool, error]
	"""
	if new_email == '':
		return [False, 'No email entered']
	if not EMAIL_RE.match(new_email + "@bergen.org"):
		return [False, "That's not a valid email."]

	user = get_user(previous_email)
	user.email = new_email
	user.email_verified = False
	memcache.set('user-'+new_email, user)
	user.put()
	email_verification(new_email, user.name)
	return [True]

def change_password(old, new, verify, email):
	'''Change a user's password'''
	if new == '':
		return [False, {'new_password_error' : "Enter a password"}]
	if old == '':
		return [False, {'password_error' : "Enter your current password"}]
	elif not PASS_RE.match(new):
		return [False, {'new_password_error' : "That's not a valid password."}]
	elif verify == '':
		return [False, {'verify_password_error' : "Verify your password"}]
	elif verify != new:
		return [False, {'verify_password_error' : "Your passwords didn't match."}]
	if not check_login(email, old)[0]:
		return [False, {'password_error' : "Incorrect password."}]

	user = get_user(email)
	(db_password, db_salt) = (user.password).split("|")
	if salted_hash(old, db_salt) == db_password:		
		salt = make_salt()
		hashed = salted_hash(new, salt)
		hashed_pass = hashed + '|' + salt

		user.password = hashed_pass
		user.put()

		memcache.set('user-'+email, user)
		memcache.set('useremail-'+str(user.email), user)
		logging.info('CACHE set user-'+email)
		logging.info('CACHE set useremail-'+str(user.email))

		cookie = LOGIN_COOKIE_NAME + '=%s|%s; Expires=%s Path=/' % (str(email), hash_str(email), remember_me())
		return [True, cookie]
	else:
		return [False, {'current_password_error' : 'Incorrect current password'}]

def get_verified(email):
	'''Gets email_verified from db from email'''
	return get_user(email, True).email_verified

def signup(email='', password='', verify='', agree='', name=''):
	"""Signs up user

	Returns:
		Dictionary of elements with error messages and 'success' : False
		OR
		{'cookie' : cookie, 'success' : True}
	"""

	to_return = {'success' : False}

	if password == '':
		to_return['password'] = "Please enter a password"
	elif not PASS_RE.match(password):
		to_return['password'] = "That's not a valid password."
	elif verify == '':
		to_return['verify'] = "Please verify your password"
	elif verify != password:
		to_return['verify'] = "Your passwords didn't match."

	if name == '':
		to_return['name'] = "Please enter your name."

	if not EMAIL_RE.match(email + "@bergen.org") and email != '':
		to_return['email'] = "That's not a valid email."
	elif not unique_email(email):
		to_return['email'] = "Email already exits!"

	if agree != 'on':
		to_return['agree'] = "You must agree to the Terms of Service to create an account"

	if len(to_return) == 1:
		salt = make_salt()
		hashed = salted_hash(password, salt)
		hashed_pass = hashed + '|' + salt

		account = Users(email = email, password = hashed_pass, email_verified = False, name = name)
		account.put()

		cookie = LOGIN_COOKIE_NAME + '=%s|%s; Expires=%s Path=/' % (str(email), hash_str(email), remember_me())
		to_return['cookie'] = cookie
		to_return['success'] = True
		email_verification(email, name)

	return to_return

def email_verification(email, name):
	'''Sends a verification email for new user'''
	link, dellink = get_unique_link(email)
	body, html = make_activation_email(email, link, dellink, name)
	try:
		mail.send_mail(sender="ClassMatch <classmatch.verify@gmail.com>",
						to="%s <%s>" % (name, email + "@bergen.org"),
						subject="Email Verification",
						body=body,
						html=html)
	except OverQuotaError:
		return 

def get_unique_link(email):
	'''Creates a verification link for new user'''
	reset_user_link(email)
	link_row = Email_Verification(email = email)
	link_row.put()
	return 'http://class-match.appspot.com/verify/' + str(link_row.key()), 'http://class-match.appspot.com/delete_email/' + str(link_row.key())

def reset_user_link(email):
	'''Deletes email verification links for user'''
	links = db.GqlQuery("SELECT * FROM Email_Verification WHERE email = :email", email = email)
	for i in links:
		i.delete()

def deleted(key):
	'''Wrong email, delete verficiation link'''
	link = db.get(key)
	if link is None:
		return False
	GET_USER.bind(email = link.email)
	user = GET_USER
	if user is None:
		return False
	memcache.delete(link.email + '_submitted')
	link.delete()
	for i in user:
		i.delete()
	return True

def delete_user_account(email):
	'''Deletes a user account and all related data (minus comments)'''
	GET_USER.bind(email = email)
	user = GET_USER
	classes = get_classes(email)
	for i in classes:
		i.delete()
	for i in user:
		i.delete()
	memcache.delete(email + '_submitted')

def verify(key):
	'''Verfies email from verification link'''
	link = db.get(key)
	if link is None:
		return False
	if datetime.datetime.now() >= link.date_created + datetime.timedelta(hours=12):
		link.delete()
		return False
	user = get_user(link.email)
	if user is None:
		return False
	user.email_verified = True
	user.put()
	memcache.delete(link.email + '_submitted')
	memcache.delete('user-'+link.email)
	link.delete()
	return True

def make_activation_email(email, link, ignore_link, name):
	html = """
	<!DOCTYPE HTML>
	<html>
	<head>
	<meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
	</head>
	<body>
		Hi %s,<br/><br/>
		Thank you for visiting and joining <a href="http://class-match.appspot.com">ClassMatch</a>!<br/><br/><br/>
		To verify your email please click this link (or copy and paste it into your browser): <a href="%s">%s</a><br/><br/>
		If you did not make an account on ClassMatch click this link: <a href="%s">%s</a>
		<br/><br/><br/>
		NOTE: Links will expire in 12 hours
	</body>
	</html>
	""" % (name, link, link, ignore_link, ignore_link)
	logging.error([link,ignore_link])

	body = """Hi %s,
	Thank you for visiting and joining ClassMatch (http://class-match.appspot.com)!
	To verify your email please click this link (or copy and paste it into your browser): %s
	If you did not make an account on ClassMatch click this link: %s
	NOTE: Links will expire in 12 hours"""% (name, link, ignore_link)

	return body, html

def get_classes(email):
	peoples_classes = db.GqlQuery("SELECT * FROM Schedule ORDER BY course DESC")
	return get_user_courses(peoples_classes,email)

def get_user_courses(peoples_classes, email):
		user_courses = []
		for people in peoples_classes:
			if people.unique_id == email:
				user_courses.append(people)
		return user_courses

def remove_user_course(email,course_name):
	course = db.GqlQuery("SELECT * FROM Schedule WHERE unique_id = :email and course = :course_name LIMIT 1", email = email, course_name = course_name).get()
	course.delete()
	# user_courses = []
	# for people in peoples_classes:
	# 	if people.unique_id == email:
	# 		user_courses.append(people)
	# 	if people.course == course_name:
	# 		user_courses.remove(people)
	# return user_courses

def list_to_str(lst):
	'''Converts a list into a string to put into HTML'''
	to_return = '['
	for i in lst:
		if i == lst[len(lst) - 1]:
			to_return += '"' + i + '"]'
		else:
			to_return += '"' + i + '",'
	return to_return

def get_courses_list():
	return list_to_str(get_all_courses())

def get_all_courses():
	'''Get all courses'''
	lst = memcache.get('all_courses')
	if not lst:
		all_users = db.GqlQuery("SELECT * FROM Schedule")
		courses = []
		for i in all_users:
			if not i.course in courses:
				courses.append(i.course)
		memcache.set('all_courses', courses)
		return courses
	return lst