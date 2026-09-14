# Third-party components

The detection proxy container uses the following unmodified third-party components.

## OWASP ModSecurity

- Project: https://github.com/owasp-modsecurity/ModSecurity
- Version: 3.0.16
- Source tag: `v3.0.16`
- License: Apache License 2.0
- License text: https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/LICENSE

## OWASP Core Rule Set

- Project: https://github.com/coreruleset/coreruleset
- Version: 4.25.1 LTS
- Pinned commit: `3b89d5a05322f448b4b74b9cadc5fb05ac6915ad`
- License: Apache License 2.0
- License text: https://github.com/coreruleset/coreruleset/blob/v4.25.1/LICENSE

The project-specific adapter, history aggregation, API, and dashboard code are not copied
from these projects. They call ModSecurity as a detection-only engine and consume CRS rule
metadata.
