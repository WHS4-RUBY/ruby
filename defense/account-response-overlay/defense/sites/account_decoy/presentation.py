"""Shared local stylesheet; no remote assets or site-specific branding."""
OPERATIONS_CSS = """
:root{color-scheme:dark;font:16px/1.65 Arial,sans-serif;color:#e8ecef;background:#111315}
body{margin:0}header{background:#333638;padding:18px max(24px,calc((100vw - 1040px)/2))}
header a{color:#e8ecef;text-decoration:none;font-size:22px;font-weight:600}
main{max-width:980px;margin:40px auto;padding:28px;background:#303436;border-radius:6px}
h1{font-size:28px;line-height:1.3;margin-top:0}h2{font-size:20px}a{color:#c4de86}
ul{padding-left:24px}li{padding:7px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;
background:#202426;padding:20px}table{border-collapse:collapse;width:100%;margin:24px 0}
th,td{text-align:left;border-bottom:1px solid #586064;padding:10px}footer{color:#bec4c9;
padding:20px 0;border-top:1px solid #586064;margin-top:32px;font-size:14px}
@media(max-width:640px){main{margin:16px;padding:18px}h1{font-size:24px}}
"""

OPERATIONS_CSS += "label{display:block;margin:14px 0}input,button{font:inherit;padding:8px;margin:4px}button{cursor:pointer}"
