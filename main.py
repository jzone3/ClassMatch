#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import logging
import jinja2
import webapp2
from google.appengine.ext import db
from google.appengine.api import memcache
from google.appengine.api import datastore_errors

try:
  # When deployed
  from google.appengine.runtime import OverQuotaError
except ImportError:
  # In the development server
  from google.appengine.runtime.apiproxy_errors import OverQuotaError

from utils import *
from secret import *

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class BaseHandler(webapp2.RequestHandler):
	'''Parent class for all handlers, shortens functions'''
	def write(self, content):
		return self.response.out.write(content)

	def rget(self, name):
		'''Gets a HTTP parameter'''
		return self.request.get(name)

	def render(self, template, params={}):
		'''Renders template using params and other parameters'''
		try:
			params['signed_in'] = self.logged_in()
			if params['signed_in']:
				params['email'] = self.get_email()
				if (template == 'schedule.html' or template == 'findclass.html') and not get_verified(params['email']):
					template = 'verify.html'
			else:
				# set email to blank
				if 'email' not in params:
					params['email'] = ''

			if template == 'account.html':
				params['verified'] = get_verified(params['email'])

			if template == 'findclass.html' and not 'index' in params.keys():
				params['findclass'] = True

			if template == 'schedule.html':
				params['all_courses'] = get_courses_list()
		except OverQuotaError:
			template = 'error.html'

		template = jinja_env.get_template(template)
		self.response.out.write(template.render(params))


	def get_email(self):
		'''Gets the email if the user cookie is valid'''
		user_cookie = self.request.cookies.get(LOGIN_COOKIE_NAME, '')
		if self.logged_in():
			return user_cookie.split("|")[0]
		else:
			return None

	def render_str(self,template,**params):
		t=jinja_env.get_template(template)
		return t.render(params)

	def logged_in(self, email = None):
		'''Checks if login cookie is valid (authenticates user)'''
		email = self.request.cookies.get(LOGIN_COOKIE_NAME, '')
		if email:
			name, hashed_name = email.split("|")
			if name and hashed_name and hash_str(name) == hashed_name:
				return True
			else:
				self.delete_cookie(LOGIN_COOKIE_NAME)
				self.delete_cookie('school')
				return False
		return False

	def set_cookie(self, cookie):
		self.response.headers.add_header('Set-Cookie', cookie)

	def delete_cookie(self, cookie):
		self.response.headers.add_header('Set-Cookie', '%s=; Path=/' % cookie)

	def remove_duplicates(self,lst):
		unique = []
		for i in lst:
			if not i in unique:
				unique.append(i)
		unique.sort()
		return unique

	def find_people_in_class(self):
		email = self.get_email()
		user_courses = get_classes(email)
		people_in_class = {}
		name = get_name(email)
		for i in user_courses:
			from_courses = Courses.get(i.course_id)
			x = from_courses.students_enrolled
			if name in x:
				x.remove(name)
			x = self.remove_duplicates(x)
			if len(x) == 0:
				continue
			stri = ''
			for student in x:
				stri += student + ", "
			people_in_class[i.course] = stri[:len(stri) - 2]
		return people_in_class
		# peoples_classes = db.GqlQuery("SELECT * FROM Schedule ORDER BY course DESC")
		# user_courses = get_classes(self.get_email())
		# people_in_class = {}
		# for people in peoples_classes:
		# 	for user_course in user_courses:
		# 		if user_course.course.strip().lower() == people.course.strip().lower() and self.get_email() != people.unique_id:
		# 			if (user_course.mods_monday == people.mods_monday and user_course.mods_tuesday == people.mods_tuesday and 
		# 				user_course.mods_wed == people.mods_wed and user_course.mods_thursday == people.mods_thursday and
		# 				user_course.mods_friday == people.mods_friday):
		# 				logging.error(people.unique_id)
		# 				if people.course in people_in_class.keys():
		# 					people_in_class[people.course] += ", " + get_name(people.unique_id)
		# 				else:
		# 					people_in_class[people.course] = get_name(people.unique_id)
		# return people_in_class

class SigninHandler(BaseHandler):
	'''Handles signing in'''
	def get(self):
		if self.logged_in():
			self.redirect('/')
		else:
			self.render('signin.html')

	def post(self):
		email = self.rget('email')
		
		email = email.lower()
		if "@bergen.org" in email:
			email = email.replace("@bergen.org","")

		blocked_time = memcache.get('loginblock-'+email)
		if blocked_time and (datetime.datetime.now() - blocked_time < datetime.timedelta(minutes=1)):
			self.render('signin.html', {'email': email, 'wrong': 'You attempted to login too many times. Try again in 1 minute.'})
			return

		correct, value = check_login(email, self.rget('password'))
		if correct:
			if self.rget('remember') == 'on':
				value = value + ' Expires=' + remember_me() + ' Path=/'
				self.set_cookie(value)
			else:
				self.set_cookie(value + ' Path=/')
			self.redirect('/')
		else:
			# log the login attempt
			tries = memcache.get('login-'+email)
			if not tries: # first attempted login
				tries = 1
				memcache.set('login-'+email, tries)
			elif tries > 4: # logged in more than 4 times
				memcache.set('loginblock-'+email, datetime.datetime.now())
			else:
				tries += 1
				memcache.set('login-'+email, tries)

			self.render('signin.html', {'email': email, 'wrong': value})

class LogoutHandler(BaseHandler):
	'''Handles logging out'''
	def get(self):
		self.delete_cookie(LOGIN_COOKIE_NAME)
		self.redirect('/')

class SignupHandler(BaseHandler):
	def get(self):
		self.render('signup.html')

	def post(self):
		
		email = self.rget('email')
		email = email.lower()
		if "@bergen.org" in email:
			email = email.replace("@bergen.org","")
		# result = signup(email = email, password = self.rget('password'), verify = self.rget('verify'), agree = self.rget('agree'), name = self.rget('name'))
		result = signup(email = email, password = self.rget('password'), verify = self.rget('verify'), agree = 'on', name = self.rget('name'))
		if result['success']:
			self.set_cookie(result['cookie'])
			self.redirect('/about')
		else:
			self.render('signup.html', {'email':email, 'password_error':result.get('password'), 'email_error':result.get('email'), 'agree_error':result.get('agree'), 'name_error':result.get('name')})

class DeleteEmailVerification(BaseHandler):
	def get(self, key):
		try:
			if deleted(key):
				self.render('email_deleted.html')
			else:
				self.error(404)
				self.render('404.html', {'blockbg':True})
		except datastore_errors.BadKeyError:
			self.error(404)
			self.render('404.html', {'blockbg':True})

class EmailVerificationHandler(BaseHandler):
	def get(self, key):
		try:
			if verify(key):
				self.render('email_verified.html')
			else:
				self.error(404)
				self.render('404.html', {'blockbg':True})
		except datastore_errors.BadKeyError:
			self.error(404)
			self.render('404.html', {'blockbg':True})

class Schedule(db.Model):
	unique_id = db.StringProperty(required = False)
	course = db.StringProperty(required = True)
	teacher = db.StringProperty(required=False)
	mods_monday = db.StringProperty(required = False)
	mods_tuesday = db.StringProperty(required = False) 
	mods_wed = db.StringProperty(required = False)
	mods_thursday = db.StringProperty(required = False)
	mods_friday = db.StringProperty(required = False)
	course_id = db.StringProperty(required = False)

class AccountHandler(BaseHandler):
	def get(self):
		if self.logged_in():
			self.render('account.html', {'account' : True})
		else:
			self.redirect('/signin')

	def post(self):
		formname = self.rget('formname')

		if formname == 'change_email':
			results = change_email(self.get_email(), self.rget('email'))
			if results[0]:
				self.render('account.html', {'account' : True, 'email_success' : True})
			else:
				self.render('account.html', {'account' : True, 'email_error' : results[1]})
		elif formname == 'change_password':
			results = change_password(self.rget('current_password'), self.rget('new_password'), self.rget('verify_new_password'), self.get_email())
			if results[0]:
				self.set_cookie(results[1])
				self.render('account.html', {'account' : True, 'password_success' : True})
			else:
				x = results[1]
				self.render('account.html', {'account' : True, 'password_error' : x.get('password_error'), 'new_password_error' : x.get('new_password_error'), 'verify_password_error' : x.get('verify_password_error')})
		elif formname == 'delete_account':
			email = self.get_email()
			if check_login(email, self.rget('password'))[0]:
				delete_user_account(email)
				self.response.headers.add_header('Set-Cookie', '%s=; Path=/' % LOGIN_COOKIE_NAME)
				self.redirect('/')
			else:
				self.render('account.html', {'account' : True, 'pass_error' : 'Incorrect Password.'})
		elif formname == 'resend':
			email = self.get_email()
			email_verification(email, get_name(email))
			self.render('account.html', {'account' : True, 'sent' : True})
		else:
			self.redirect('/account')

class AboutHandler(BaseHandler):
	def get(self):
		self.render('about.html', {'about' : True})

class MainHandler(BaseHandler):
	def get(self):
		if self.logged_in():
			#try:
			self.render('findclass.html', {'peoples' : self.find_people_in_class(), 'index' : True})
			#except:
			#	self.render('error.html')
		else:
			self.render("index.html")

class Submit(BaseHandler):
	def render_page(self,error=None,user_courses=""):
		if error:
			self.render('schedule.html',{'schedule' : True, 'error' : error, 'user_courses' : user_courses})
		else:
			self.render('schedule.html',{'schedule' : True, 'user_courses' : user_courses})
	def get(self):
		if self.logged_in():
			#peoples_classes = db.GqlQuery("SELECT * FROM Schedule ORDER BY course DESC")
			user_courses = get_classes(self.get_email())
			for course in user_courses:
				if course.mods_monday == '':
					course.mods_monday = 'None'
				if course.mods_tuesday == '':
					course.mods_tuesday = 'None'
				if course.mods_wed == '':
					course.mods_wed = 'None'
				if course.mods_thursday == '':
					course.mods_thursday = 'None'
				if course.mods_friday == '':
					course.mods_friday = 'None'
			self.render_page(user_courses=user_courses)
		else:
			self.redirect('/signin')
	def post(self):
		q = ''
		email = self.get_email()
		while True:
			course = self.request.get("course" + str(q)).strip()
			teacher = self.request.get("teacher"+ str(q)).strip()
			mods_monday = self.request.get("monday" + str(q)).strip()
			mods_tuesday = self.request.get("tuesday" + str(q)).strip()
			mods_wed = self.request.get("wednesday" + str(q)).strip()
			mods_thursday = self.request.get("thursday" + str(q)).strip()
			mods_friday = self.request.get("friday" + str(q)).strip()
			if q == '':
				q = 2
			else:
				q += 1
			if course:
				course_id = get_course_id(course, mods_monday, mods_tuesday, mods_wed, mods_thursday, mods_friday, email)
				s = Schedule(unique_id=email , course=course,teacher=teacher,mods_monday=mods_monday,mods_tuesday=mods_tuesday,
					mods_wed=mods_wed,mods_thursday = mods_thursday,mods_friday=mods_friday,course_id=course_id)
				s.put()
				course_to_add = Courses.get(course_id)
				course_to_add.students_enrolled.append(get_name(email))
				course_to_add.put()
			else:
				break
			# DELETE THE CACHE
		self.redirect('/findclassmates')

class FindClass(BaseHandler):
	def get(self):
		'''Gets the users courses'''
		self.render('findclass.html',{'peoples':self.find_people_in_class()})

class DeleteEmailVerification(BaseHandler):
	def get(self, key):
		try:
			if deleted(key):
				self.render('email_deleted.html')
			else:
				self.error(404)
				self.render('404.html', {'blockbg':True})
		except datastore_errors.BadKeyError:
			self.error(404)
			self.render('404.html', {'blockbg':True})

class DeleteClass(BaseHandler):
	def get(self):
		self.redirect('/schedule/?')
	def post(self):
		email = self.get_email()
		remove_user_course(email, self.rget('course'))
		self.redirect('/findclassmates')

app = webapp2.WSGIApplication([
	('/?', MainHandler),
	('/signin/?', SigninHandler),
	('/account/?', AccountHandler),
	('/logout/?', LogoutHandler),
	('/signup/?', SignupHandler),
	('/verify/([^/]+)?', EmailVerificationHandler),
	('/delete_email/?', DeleteEmailVerification),
	('/schedule/?', Submit),
	('/about/?', AboutHandler),
	('/findclassmates/?',FindClass),
	('/delete_email/([^/]+)?', DeleteEmailVerification),
	('/delete_class/?',DeleteClass),
	# ('/delete_account/?', DeleteAccountHandler)
], debug=True)
