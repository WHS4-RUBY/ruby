"""The /ops + /ftp account decoy this package serves.

The directory used to be called juice_shop, but every path in it is the overlay's own
decoy namespace, not the protected site's. The Juice-Shop-specific parts are the
/api/Challenges reply in facade.py and cycle.py and the synthetic-success route set in
false_success.py; those are gated on settings.site_adapter.
"""
