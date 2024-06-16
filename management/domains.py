#!/usr/local/bin/mailinabox/env/bin/python

from mailconfig import open_database
import sqlite3, re
import utils

# String list of possible options
# Options are togglable booleans
# In the database, true
# Not in the database, false
POSSIBLE_OPTIONS = [
    "no-web", # Not serving web and not checking A/AAAA records
]

def validate_domain(domain):
    return re.match(r"[a-zA-Z0-9\-\.]+", domain)

def get_domains(env):
    # Returns a flat, sorted list of all domain names.
    c = open_database(env)
    c.execute('SELECT domain FROM domains')
    domains = [ row[0] for row in c.fetchall() ]
    return utils.sort_domains(domains, env)

def get_domains_ex(env):
    # Returns a list of domains with their options.
    domains = []
    c = open_database(env)
    c.execute('SELECT domain, options FROM domains')
    for domain, options in c.fetchall():
        domains.append({
            "domain": domain,
            "options": parse_options(options)
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
    conn, c = open_database(env, with_connection=True)

    # add the domain to the database
    try:
        c.execute("INSERT INTO domains (domain, options) VALUES (?, ?)",
                  (domain, '\n'.join(options)))
    except sqlite3.IntegrityError:
        return ("Domain already exists.", 400)

    conn.commit()
    return None

def remove_domain(domain, env):
    # get the database
    conn, c = open_database(env, with_connection=True)

    # remove
    c.execute("DELETE FROM domains WHERE domain=?", (domain,))
    if c.rowcount != 1:
        return ("That's not a domain (%s)." % domain, 400)
    conn.commit()

    return None

def get_domain_options(domain, env):
    c = open_database(env)
    c.execute('SELECT options FROM domains WHERE domain=?', (domain,))
    rows = c.fetchall()
    if len(rows) != 1:
        return ("That's not a domain (%s)." % domain, 400)
    return parse_options(rows[0][0])

def set_domain_option(domain, option, value: bool, env):
    if option not in POSSIBLE_OPTIONS:
        return ("That's not a valid option (%s)." % option, 400)
    
    opts = get_domain_options(domain, env)
    if isinstance(opts, tuple): return opts # error

    opts[option] = value

    # commit to database
    conn, c = open_database(env, with_connection=True)
    c.execute("UPDATE domains SET options=? WHERE domain=?",
              (encode_options(opts), domain))
    if c.rowcount != 1:
        return ("Something went wrong.", 400)
    conn.commit()

    return "OK"