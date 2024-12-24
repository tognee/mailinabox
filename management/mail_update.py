#!/usr/local/lib/mailinabox/env/bin/python

def kick(env, mail_result=None):
	import idna

	from mail_aliases import (
		get_system_administrator,
		get_required_aliases,
		add_auto_aliases,
		get_mail_aliases,
		remove_mail_alias
	)
	from mail_domains import get_domains
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
	for domain in get_domains(env):
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
