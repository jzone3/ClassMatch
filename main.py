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
import jinja2
import webapp2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class BaseHandler(webapp2.RequestHandler):
		'''Parent class for all handlers, shortens functions'''
	def write(self, content):
		return self.response.out.write(content)

	def rget(self, name):
		'''Gets a HTTP parameter'''
		return self.request.get(name)

	def get_username(self):
		'''Gets the username if the user cookie is valid'''
		user_cookie = self.request.cookies.get(LOGIN_COOKIE_NAME, '')
		if self.logged_in():
			return user_cookie.split("|")[0]
		else:
			return None

	def logged_in(self, username = None):
		'''Checks if login cookie is valid (authenticates user)'''
		username = self.request.cookies.get(LOGIN_COOKIE_NAME, '')
		if username:
			name, hashed_name = username.split("|")
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

class LogoutHandler(BaseHandler):
	'''Handles logging out'''
	def get(self):
		self.delete_cookie(LOGIN_COOKIE_NAME)
		self.redirect('/')

class DeleteAccountHandler(BaseHandler):
	def get(self):
		username = self.get_username()
		if username:
			self.render('delete_account.html') #MAKE THIS
		else:
			self.redirect('/')

	def post(self):
		username = self.get_username()
		if username:			
			password = self.rget('password')
			if check_login(username, password):
				feedback = self.rget('feedback')
				self.delete_account(username)
			else:
				self.render('/delete_account')
		else:
			self.redirect('/')

	def delete_account(self, username):
		delete_user_account(username) #MAKE THIS
		self.delete_cookie(LOGIN_COOKIE_NAME)
		self.redirect('/')

class MainHandler(BaseHandler):
    def get(self):
        self.render("index.html")
class Schedule(BaseHandler):
	def get(self):
		self.render("schedule.html")

app = webapp2.WSGIApplication([
    ('/?', MainHandler),
    ('/logout/?', LogoutHandler),
    ('/delete_account/?', DeleteAccountHandler),
    ('/schedule',Schedule)
], debug=True)
