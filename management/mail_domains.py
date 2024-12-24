#!/usr/local/bin/mailinabox/env/bin/python

import sqlite3, re
import utils
from publicsuffixlist import PublicSuffixList
from mail_update import kick
import idna

# TODO: Add support for updated list
psl = PublicSuffixList()

# String list of possible options
# Options are togglable booleans
# In the database, true
# Not in the database, false
POSSIBLE_OPTIONS = [
	"web", # Serving web and checking A/AAAA records for @ and www.
]

def sanitize_idn(domain):
	try:
		return idna.encode(domain, uts46=True).decode('ascii')
	except idna.IDNAError:
		return domain

def prettify_idn(domain):
	try:
		return idna.decode(domain.encode('ascii'))
	except idna.IDNAError:
		return domain

def validate_domain(domain):
	# Check for valid domain
	has_valid_chars = re.match(r"[a-zA-Z0-9\-\.]+", domain)
	is_public = psl.is_public(domain)
	return has_valid_chars and not is_public

def get_domain_id(c, domain):
	# This is purly a database helper, should
	# be used only with a db context

	# Make sure the domain is idn safe
	domain = sanitize_idn(domain)

	# Get the domain id
	c.execute("SELECT id FROM domains WHERE domain=?", (domain,))
	domain_id = c.fetchone()
	if domain_id is None:
		return None
	return domain_id[0]

def get_domains(env, users_only=False, prettify=False):
	# Returns a flat, sorted list of all domain names.
	c = utils.open_database(env)
	query = 'SELECT domain FROM domains'
	if users_only:
		query += ' WHERE id IN (SELECT domain_id FROM users)'
	c.execute(query)
	domains = [ prettify_idn(row[0]) if prettify else row[0] for row in c.fetchall() ]
	return utils.sort_domains(domains, env)

def get_domains_ex(env):
	# Returns a list of domains with their options.
	# [
	#   {
	#     "id": 1,
	#     "domain": "example.com",
	#     "prettified": "example.com",
	#     "options": {
	#       "web": True,
	#     },
	#     "user_count": 1
	#     "alias_count": 1
	#     "auto_alias_count": 1
	#   },
	# ]
	domains = []
	c = utils.open_database(env)
	c.execute('SELECT id, domain, options, (SELECT COUNT(*) FROM users WHERE domain_id=id) as user_count, (SELECT COUNT(*) FROM aliases WHERE source_domain_id=id) as alias_count, (SELECT COUNT(*) FROM auto_aliases WHERE source_domain_id=id) as auto_alias_count FROM domains')
	for id, domain, options, user_count, alias_count, auto_alias_count in c.fetchall():
		domains.append({
			"id": id,
			"domain": domain,
			"prettified": prettify_idn(domain),
			"options": parse_options(options),
			"user_count": user_count,
			"alias_count": alias_count,
			"auto_alias_count": auto_alias_count
		})

	return domains

def parse_options(options):
	option_list = options.split('\n')
	return {opt: opt in option_list for opt in POSSIBLE_OPTIONS}

def encode_options(options):
	result = []
	for option, value in options.items():
		if value:
			result.append(option)
	return '\n'.join(result)

def add_domain(domain, options, env):
	if domain.strip() == "":
		return ("No domain provided.", 400)
	domain = sanitize_idn(domain)
	if not validate_domain(domain):
		return ("That's not a valid domain (%s)." % domain, 400)

	# validate options
	if options is None or options.strip() == "":
		options = []
	else:
		options = options.split('\n')
		for option in options:
			if option not in POSSIBLE_OPTIONS:
				return ("That's not a valid option (%s)." % option, 400)

	# get the database
	conn, c = utils.open_database(env, with_connection=True)

	# add the domain to the database
	try:
		c.execute("INSERT INTO domains (domain, options) VALUES (?, ?)",
				  (domain, '\n'.join(options)))
	except sqlite3.IntegrityError:
		return ("Domain already exists.", 400)

	conn.commit()
	return kick(env)

def remove_domain(domain, env):
	# get the database
	conn, c = utils.open_database(env, with_connection=True)
	domain = sanitize_idn(domain)

	# get the domain id from the database
	c.execute("SELECT id FROM domains WHERE domain=?", (domain,))
	if c.rowcount != 1:
		return ("That's not a domain (%s)." % domain, 400)
	domain_id = c.fetchone()[0]

	# check that there are no emails using this domain
	c.execute("SELECT COUNT(*) FROM users WHERE domain_id=?", (domain_id,))
	if c.fetchone()[0] > 0:
		return ("That domain is in use.", 400)

	# remove
	c.execute("DELETE FROM domains WHERE id=?", (domain_id,))
	conn.commit()

	return kick(env)

def get_domain_options(domain, env):
	domain = sanitize_idn(domain)
	c = utils.open_database(env)
	c.execute('SELECT options FROM domains WHERE domain=?', (domain,))
	rows = c.fetchall()
	if len(rows) != 1:
		return ("That's not a domain (%s)." % domain, 400)
	return parse_options(rows[0][0])

def update_domain(domain, options, env):
	domain = sanitize_idn(domain)
	if options is None or options.strip() == "":
		options = []
	else:
		options = options.split('\n')
		for option in options:
			if option not in POSSIBLE_OPTIONS:
				return ("That's not a valid option (%s)." % option, 400)

	conn, c = utils.open_database(env, with_connection=True)

	c.execute("UPDATE domains SET options=? WHERE domain=?",
			  ('\n'.join(options), domain))
	if c.rowcount != 1:
		return ("Something went wrong.", 400)
	conn.commit()

	return kick(env, "OK")

def set_domain_option(domain, option, value: bool, env):
	domain = sanitize_idn(domain)
	if option not in POSSIBLE_OPTIONS:
		return ("That's not a valid option (%s)." % option, 400)

	opts = get_domain_options(domain, env)
	if isinstance(opts, tuple): return opts # error

	opts[option] = value

	# commit to database
	conn, c = utils.open_database(env, with_connection=True)
	c.execute("UPDATE domains SET options=? WHERE domain=?",
			  (encode_options(opts), domain))
	if c.rowcount != 1:
		return ("Something went wrong.", 400)
	conn.commit()

	return kick(env, "OK")
