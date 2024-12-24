#!/usr/local/lib/mailinabox/env/bin/python

# NOTE:
# This script is run both using the system-wide Python 3
# interpreter (/usr/bin/python3) as well as through the
# virtualenv (/usr/local/lib/mailinabox/env). So only
# import packages at the top level of this script that
# are installed in *both* contexts. We use the system-wide
# Python 3 in setup/questions.sh to validate the email
# address entered by the user.

import os, sqlite3, re
import utils
from email_validator import validate_email as validate_email_, EmailNotValidError
import idna
from domains import get_domain_id


# def get_mail_domains(env, filter_aliases=lambda alias : True, users_only=False):
# 	# Returns the domain names (IDNA-encoded) of all of the email addresses
# 	# configured on the system. If users_only is True, only return domains
# 	# with email addresses that correspond to user accounts. Exclude Unicode
# 	# forms of domain names listed in the automatic aliases table.
# 	domains = []
# 	domains.extend([get_domain(login, as_unicode=False) for login in get_mail_users(env)])
# 	if not users_only:
# 		domains.extend([get_domain(address, as_unicode=False) for address, _, _, auto in get_mail_aliases(env) if filter_aliases(address) and not auto ])
# 	return set(domains)

def kick(env, mail_result=None):
	results = []

	# Include the current operation's result in output.

	if mail_result is not None:
		results.append(mail_result + "\n")

	auto_aliases = { }

	# Map required aliases to the administrator alias (which should be created manually).
	administrator = get_system_administrator(env)
	required_aliases = get_required_aliases(env)
	for alias in required_aliases:
		if alias == administrator: continue # don't make an alias from the administrator to itself --- this alias must be created manually
		auto_aliases[alias] = administrator

	# Add domain maps from Unicode forms of IDNA domains to the ASCII forms stored in the alias table.
	for domain in get_mail_domains(env):
		try:
			domain_unicode = idna.decode(domain.encode("ascii"))
			if domain == domain_unicode: continue # not an IDNA/Unicode domain
			auto_aliases["@" + domain_unicode] = "@" + domain
		except (ValueError, UnicodeError, idna.IDNAError):
			continue

	add_auto_aliases(auto_aliases, env)

	# Remove auto-generated postmaster/admin/abuse alises from the main aliases table.
	# They are now stored in the auto_aliases table.
	for address, forwards_to, _permitted_senders, auto in get_mail_aliases(env):
		user, domain = address.split("@")
		if user in {"postmaster", "admin", "abuse"} \
			and address not in required_aliases \
			and forwards_to == get_system_administrator(env) \
			and not auto:
			remove_mail_alias(address, env, do_kick=False)
			results.append(f"removed alias {address} (was to {forwards_to}; domain no longer used for email)\n")

	# Update DNS and nginx in case any domains are added/removed.

	from dns_update import do_dns_update
	results.append( do_dns_update(env) )

	from web_update import do_web_update
	results.append( do_web_update(env) )

	return "".join(s for s in results if s != "")


if __name__ == "__main__":
	import sys
	if len(sys.argv) > 1 and sys.argv[1] == "update":
		from utils import load_environment
		print(kick(load_environment()))
