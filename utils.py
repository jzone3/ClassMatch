GET_USER = db.GqlQuery("SELECT * FROM Users WHERE email = :email LIMIT 1")

def remember_me():
	'''Returns expiration time for remember me cookie'''
	expiration = datetime.datetime.now() + datetime.timedelta(days=50)
	return expiration.strftime("%a, %d-%b-%Y %H:%M:%S PST")

def hash_str(string):
	'''Hashes a string for user cookie'''
	return hmac.new(secret.SECRET, str(string), hashlib.sha512).hexdigest()

def salted_hash(password, salt):
	'''Hashes a string for user password'''
	return hashlib.sha256(password + salt).hexdigest()

def make_salt():
	'''Makes random salt for user cookie'''
	return ''.join(random.choice(string.letters) for x in xrange(5))

def get_user(email):
	'''Get User object from email'''
	user = memcache.get('user-'+email)
	if user:
		logging.info('CACHE GET_USER: '+email)
		return user
	else:
		logging.info('DB GET_USER: '+email)
		GET_USER.bind(email = email)
		user = GET_USER.get()

		memcache.set('user-'+email, user)
		logging.info('CACHE set user-'+email)

		return user

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

def get_confirmed(username):
	'''Gets confirmed from db from username'''
	q = Users.all()
	q.filter('username =', username)
	result = q.get()
	if result:
		return result.confirmed
	else:
		return None

def signup(email='', password='', verify='', agree=''):
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

	if not EMAIL_RE.match(email) and email != '':
		to_return['email'] = "That's not a valid email." + email
	elif not unique_email(email):
		to_return['email'] = "Email already exits!"

	if agree != 'on':
		to_return['agree'] = "You must agree to the Terms of Service to create an account"

	if len(to_return) == 1:
		salt = make_salt()
		hashed = salted_hash(password, salt)
		hashed_pass = hashed + '|' + salt

		account = Users(email = email, password = hashed_pass, confirmed = False)
		account.put()

		cookie = LOGIN_COOKIE_NAME + '=%s|%s; Expires=%s Path=/' % (str(email), hash_str(email), remember_me())
		to_return['cookie'] = cookie
		to_return['success'] = True
		email_verification(email, email)

	return to_return

def email_verification(email):
	'''Sends a verification email for new user'''
	link, dellink = get_unique_link(email)
	body, html = make_activation_email(email, link, dellink)
	mail.send_mail(sender="ClassMatch <info@class-match.appspot.com>",
						to="%s <%s>" % (email, email + "@bergen.org"),
						subject="Email Verification",
						body=body,
						html=html)

def get_unique_link(email):
	'''Creates a verification link for new user'''
	reset_user_link(email)
	link_row = Email_Verification(email = email)
	link_row.put()
	return 'http://class-match.appsot.com/verify/' + str(link_row.key()), 'http://class-match.appsot.com/delete_email/' + str(link_row.key())

def reset_user_link(email):
	'''Deletes email verification links for user'''
	links = db.GqlQuery("SELECT * FROM Email_Verification WHERE email = :email", email = email)
	for i in links:
		i.delete()

def verify(key):
	'''Verfies email from verification link'''
	link = db.get(key)
	if link is None:
		return False
	if datetime.datetime.now() >= link.date_created + datetime.timedelta(hours=12):
		link.delete()
		return False
	user = get_user(link.username)
	if user is None:
		return False
	user.email_verified = True
	user.put()
	link.delete()
	return True