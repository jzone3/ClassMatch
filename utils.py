import re
import hmac
import hashlib
import datetime
import random
import string

SECRET = "just_for_practice"
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
	if USER_RE.match(username):
		return True
	else:
		return False
def valid_password(password):
	if PASSWORD_RE.match(password):
		return True
	else:
		return False
def valid_email(email):
	if EMAIL_RE.match(email):
		return True
	else:
		return False
def hash_str(s):
	return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s,hash_str(s))

def check_secure_val(h):
	val = h.split("|")[0]
	if h == make_secure_val(val):
		return val

def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name,pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw+ salt).hexdigest()
	return "%s|%s" %(h,salt)

def valid_pw(name,pw,h):
	salt = h.split("|")[1]
	return h == make_pw_hash(name,pw,salt)