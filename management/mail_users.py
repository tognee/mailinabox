import sqlite3
import os
import utils
from mail_utils import validate_email, is_dcv_address
from mail_domains import get_domain_id
from mail_update import kick

def get_mail_users(env):
	# Returns a flat, sorted list of all user accounts.
	c = utils.open_database(env)
	c.execute("SELECT (username || '@' || domain) as email FROM users JOIN domains ON domains.id = domain_id")
	users = [ row[0] for row in c.fetchall() ]
	return utils.sort_email_addresses(users, env)

def get_mail_users_ex(env, with_archived=False):
	# Returns a complex data structure of all user accounts, optionally
	# including archived (status="inactive") accounts.
	#
	# [
	#   {
	#     domain: "domain.tld",
	#     users: [
	#       {
	#         email: "name@domain.tld",
	#         username: "name",
	#         domain: "domain.tld",
	#         privileges: [ "priv1", "priv2", ... ],
	#         status: "active" | "inactive",
	#       },
	#       ...
	#     ]
	#   },
	#   ...
	# ]

	# Get users and their privileges.
	users = []
	active_accounts = set()
	c = utils.open_database(env)
	c.execute('SELECT username, domain, privileges FROM users INNER JOIN domains ON users.domain_id=domains.id')
	for username, domain, privileges in c.fetchall():
		email = f"{username}@{domain}"
		active_accounts.add(email)

		user = {
			"email": email,
			"username": username,
			"domain": domain,
			"privileges": parse_privs(privileges),
			"status": "active",
		}
		users.append(user)

	# Add in archived accounts.
	if with_archived:
		root = os.path.join(env['STORAGE_ROOT'], 'mail/mailboxes')
		for domain in os.listdir(root):
			if os.path.isdir(os.path.join(root, domain)):
				for user in os.listdir(os.path.join(root, domain)):
					email = user + "@" + domain
					mbox = os.path.join(root, domain, user)
					if email in active_accounts: continue
					user = {
						"email": email,
						"username": user,
						"domain": domain,
						"privileges": [],
						"status": "inactive",
						"mailbox": mbox,
					}
					users.append(user)

	# Group by domain.
	domains = { }
	for user in users:
		domain = user["domain"]
		if domain not in domains:
			domains[domain] = {
				"domain": domain,
				"users": []
				}
		domains[domain]["users"].append(user)

	# Sort domains.
	domains = [domains[domain] for domain in utils.sort_domains(domains.keys(), env)]

	# Sort users within each domain first by status then lexicographically by email address.
	for domain in domains:
		domain["users"].sort(key = lambda user : (user["status"] != "active", user["email"]))

	return domains

def get_admins(env):
	# Returns a set of users with admin privileges.
	users = set()
	for domain in get_mail_users_ex(env):
		for user in domain["users"]:
			if "admin" in user["privileges"]:
				users.add(user["email"])
	return users


def add_mail_user(email, pw, privs, env):
	# validate email
	if email.strip() == "":
		return ("No email address provided.", 400)
	[username, domain] = email.split("@", 1)
	if username.strip() == "":
		return ("No username provided.", 400)
	if domain.strip() == "":
		return ("No domain provided.", 400)
	if not validate_email(email):
		return ("Invalid email address.", 400)
	elif not validate_email(email, mode='user'):
		return ("User account email addresses may only use the lowercase ASCII letters a-z, the digits 0-9, underscore (_), hyphen (-), and period (.).", 400)
	elif is_dcv_address(email) and len(get_mail_users(env)) > 0:
		# Make domain control validation hijacking a little harder to mess up by preventing the usual
		# addresses used for DCV from being user accounts. Except let it be the first account because
		# during box setup the user won't know the rules.
		return ("You may not make a user account for that address because it is frequently used for domain control validation. Use an alias instead if necessary.", 400)

	# validate password
	validate_password(pw)

	# validate privileges
	if privs is None or privs.strip() == "":
		privs = []
	else:
		privs = privs.split("\n")
		for p in privs:
			validation = validate_privilege(p)
			if validation: return validation

	# get the database
	conn, c = utils.open_database(env, with_connection=True)

	# get domain id
	domain_id = get_domain_id(c, domain)
	if domain_id is None:
		return ("That's not a domain (%s)." % domain, 400)

	# hash the password
	pw = hash_password(pw)

	# add the user to the database
	try:
		c.execute("INSERT INTO users (username, domain_id, password, privileges) VALUES (?, ?, ?, ?)",
			(username, domain_id, pw, "\n".join(privs)))
	except sqlite3.IntegrityError:
		return ("User already exists.", 400)

	# write databasebefore next step
	conn.commit()

	return "mail user added"

def set_mail_password(email, pw, env):
	# validate email
	if email.strip() == "":
		return ("No email address provided.", 400)

	# get the database
	conn, c = utils.open_database(env, with_connection=True)

	username, domain = email.split("@", 1)
	# get domain id
	domain_id = get_domain_id(c, domain)
	if domain_id is None:
		return ("That's not a domain (%s)." % domain, 400)

	# validate that password is acceptable
	validate_password(pw)

	# hash the password
	pw = hash_password(pw)

	# update the database
	c.execute("UPDATE users SET password=? WHERE username=? AND domain_id=?", (pw, username, domain_id))
	if c.rowcount != 1:
		email = username + "@" + domain
		return ("That's not a user (%s)." % email, 400)
	conn.commit()
	return "OK"

def hash_password(pw):
	# Turn the plain password into a Dovecot-format hashed password, meaning
	# something like "{SCHEME}hashedpassworddata".
	# http://wiki2.dovecot.org/Authentication/PasswordSchemes
	return utils.shell('check_output', ["/usr/bin/doveadm", "pw", "-s", "SHA512-CRYPT", "-p", pw]).strip()

def get_mail_password(email, env):
	# Gets the hashed password for a user. Passwords are stored in Dovecot's
	# password format, with a prefixed scheme.
	# http://wiki2.dovecot.org/Authentication/PasswordSchemes


	# validate email
	if email.strip() == "":
		return ("No email address provided.", 400)
	[username, domain] = email.split("@", 1)

	# update the database
	c = utils.open_database(env)

	domain_id = get_domain_id(c, domain)
	if domain_id is None:
		raise ValueError("That's not a domain (%s)." % domain)

	c.execute('SELECT password FROM users WHERE username=? AND domain_id=?', (username, domain_id))
	rows = c.fetchall()
	if len(rows) != 1:
		raise ValueError("That's not a user (%s)." % email)
	return rows[0][0]

def remove_mail_user(email, env):
	# validate email
	if email.strip() == "":
		return ("No email address provided.", 400)
	[username, domain] = email.split("@", 1)
	# remove
	conn, c = utils.open_database(env, with_connection=True)

	domain_id = get_domain_id(c, domain)
	if domain_id is None:
		return ("That's not a domain (%s)." % domain, 400)

	c.execute("DELETE FROM users WHERE username=? AND domain_id=?", (username, domain_id))
	if c.rowcount != 1:
		email = username + "@" + domain
		return ("That's not a user (%s)." % email, 400)
	conn.commit()

	# Update things in case any domains are removed.
	return kick(env, "mail user removed")

def parse_privs(value):
	return [p for p in value.split("\n") if p.strip() != ""]

def get_mail_user_privileges(email, env, empty_on_error=False):
	# validate email
	if email.strip() == "":
		return ("No email address provided.", 400)
	[username, domain] = email.split("@", 1)
	# get privs
	c = utils.open_database(env)
	domain_id = get_domain_id(c, domain)
	if domain_id is None:
		if empty_on_error: return []
		return ("That's not a domain (%s)." % domain, 400)

	c.execute('SELECT privileges FROM users WHERE username=? AND domain_id=?', (username, domain_id))
	rows = c.fetchall()
	if len(rows) != 1:
		if empty_on_error: return []
		return ("That's not a user (%s)." % email, 400)
	return parse_privs(rows[0][0])

def validate_privilege(priv):
	if "\n" in priv or priv.strip() == "":
		return ("That's not a valid privilege (%s)." % priv, 400)
	return None

def add_remove_mail_user_privilege(email, priv, action, env):
	# validate email
	if email.strip() == "":
		return ("No email address provided.", 400)
	[username, domain] = email.split("@", 1)

	# validate
	validation = validate_privilege(priv)
	if validation: return validation

	# get existing privs, but may fail
	privs = get_mail_user_privileges(email, env)
	if isinstance(privs, tuple): return privs # error

	# update privs set
	if action == "add":
		if priv not in privs:
			privs.append(priv)
	elif action == "remove":
		privs = [p for p in privs if p != priv]
	else:
		return ("Invalid action.", 400)

	# commit to database
	conn, c = utils.open_database(env, with_connection=True)

	domain_id = get_domain_id(c, domain)
	if domain_id is None:
		return ("That's not a domain (%s)." % domain, 400)

	c.execute("UPDATE users SET privileges=? WHERE username=? AND domain_id=?", ("\n".join(privs), username, domain_id))
	if c.rowcount != 1:
		return ("Something went wrong.", 400)
	conn.commit()

	return "OK"

def validate_password(pw):
	# validate password
	if pw.strip() == "":
		msg = "No password provided."
		raise ValueError(msg)
	if len(pw) < 8:
		msg = "Passwords must be at least eight characters."
		raise ValueError(msg)
