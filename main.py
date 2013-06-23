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
		params['signed_in'] = self.logged_in()
		if params['signed_in']:
			params['email'] = self.get_email()
			if template == 'schedule.html' and not get_verified(params['email']):
				template = 'verify.html'
		else:
			# set email to blank
			if 'email' not in params:
				params['email'] = ''

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

class SigninHandler(BaseHandler):
	'''Handles signing in'''
	def get(self):
		if self.logged_in():
			self.redirect('/')
		else:
			self.render('signin.html')

	def post(self):
		email = self.rget('email')

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
		
		result = signup(email = email, password = self.rget('password'), verify = self.rget('verify'), agree = self.rget('agree'))

		if result['success']:
			self.set_cookie(result['cookie'])
			self.redirect('/')
		else:
			self.render('signup.html', {'email':email, 'password_error':result.get('password'), 'email_error':result.get('email'), 'agree_error':result.get('agree')})

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
	mods_monday = db.StringProperty(required = False)
	mods_tuesday = db.StringProperty(required = False) 
	mods_wed = db.StringProperty(required = False) 
	mods_thursday = db.StringProperty(required = False) 
	mods_friday = db.StringProperty(required = False) 

class AccountHandler(BaseHandler):
	def get(self):
		self.render('account.html', {'account' : True})

class AboutHandler(BaseHandler):
	def get(self):
		self.render('about.html', {'about' : True})

class MainHandler(BaseHandler):
    def get(self):
        self.render("index.html")

class Submit(BaseHandler):
	def render_page(self):
		self.render('schedule.html',{'schedule' : True})
	def get(self):
		if self.logged_in():
			self.render_page()
		else:
			self.redirect('/signin')
	def post(self):
		course = self.request.get("course")
		mods_monday = self.request.get("monday")
		mods_tuesday = self.request.get("tuesday")
		mods_wed = self.request.get("wednesday")
		mods_thursday = self.request.get("thursday")
		mods_friday = self.request.get("friday")
		if course:
			s = Schedule(unique_id= self.get_email() , course=course,mods_monday=mods_monday,mods_tuesday=mods_tuesday,
				mods_wed=mods_wed,mods_thursday = mods_thursday,mods_friday=mods_friday )
			s.put()
			self.redirect('/findclass')
		else:
			error="Please enter course name and number of mods"
			self.render_page()

class FindClass(BaseHandler):
	def get(self):
		'''Gets the users courses'''
		peoples_classes = db.GqlQuery("SELECT * FROM Schedule ORDER BY course  DESC")
		user_courses = []
		for people in peoples_classes:
			if people.unique_id == self.get_email():
				user_courses.append(people)
		i = 0
		people_in_class = {}
		for people in peoples_classes:
			user_course = user_courses[i]
			if (user_course == people.course) and (self.get_email() != people.unique_id):
				if (user_course.mods_monday == people.mods_monday and user_course.mods_tuesday == people.mods_tuesday and 
					user_course.mods_wed == people.mods_wed and user_course.mods_thursday == people.mods_thursday and
					user_course.mods_friday == people.mods_friday):
					people_in_class[people.course] = people.unique_id

		self.render('findclass.html',{'peoples':people_in_class})

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
	('/findclass/?',FindClass),
	('/delete_email/([^/]+)?', DeleteEmailVerification)
	# ('/delete_account/?', DeleteAccountHandler)
], debug=True)
