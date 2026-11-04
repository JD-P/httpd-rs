# Differential report: vapached vs. Apache httpd

Generated: 2026-11-04 02:06:46Z

6 divergence(s):

- **rewrite [P] Proxy deny**: status 200 != 403; content-type: 'text/plain; charset=UTF-8' != 'text/html; charset=iso-8859-1'
- **OPTIONS ***: allow: None != 'GET, HEAD, POST, OPTIONS'
- **POST static**: status 200 != 405; content-type: 'text/plain; charset=UTF-8' != 'text/html; charset=iso-8859-1'; accept-ranges: 'bytes' != None; allow: None != 'GET, HEAD, OPTIONS'
- **416 range**: content-range: None != 'bytes */12'
- **TRACE off**: allow: '' != 'GET, HEAD, POST, OPTIONS'
- **negative group without provider**: status 200 != 403; content-type: 'text/plain; charset=UTF-8' != 'text/html; charset=iso-8859-1'; accept-ranges: 'bytes' != None
