"""The /ops + /ftp account decoy this package serves.

The directory used to be called juice_shop, but every path in it is the overlay's own
decoy namespace, not the protected site's. The parts that depend on the protected site --
the challenge API reply in facade.py and cycle.py, the synthetic-success route set in
false_success.py, and the account path prefixes in engagement.py and cycle.py -- are
declared by the site profile (challenge_api, synthetic_success, account_api_prefixes).
There is no site_adapter switch any more: adding a site is a profile, not a code change.
"""
