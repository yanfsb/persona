#!/usr/bin/env python3
import http.server
import os
import subprocess
import sys
import urllib.parse

root, race_file, marker = sys.argv[1:]

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.run_backend()

    def do_POST(self):
        self.run_backend()

    def run_backend(self):
        parsed = urllib.parse.urlsplit(self.path)
        with open(marker + ".requests", "a", encoding="utf-8") as log:
            log.write(self.command + " " + self.path + "\\n")
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        env = os.environ.copy()
        env.update({
            "GIT_PROJECT_ROOT": root,
            "GIT_HTTP_EXPORT_ALL": "1",
            "PATH_INFO": urllib.parse.unquote(parsed.path),
            "QUERY_STRING": parsed.query,
            "REQUEST_METHOD": self.command,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(len(body)),
            "REMOTE_USER": "",
            "REMOTE_ADDR": "127.0.0.1",
            "SERVER_PROTOCOL": self.request_version,
            "HTTP_GIT_PROTOCOL": self.headers.get("Git-Protocol", ""),
        })
        result = subprocess.run(["git", "http-backend"], input=body, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        headers, separator, payload = result.stdout.partition(b"\r\n\r\n")
        if not separator:
            headers, separator, payload = result.stdout.partition(b"\n\n")
        status = 200
        response_headers = []
        for line in headers.decode("latin-1").replace("\r", "").split("\n"):
            if line.lower().startswith("status:"):
                status = int(line.split(None, 1)[1].split()[0])
            elif ":" in line:
                key, value = line.split(":", 1)
                response_headers.append((key, value.strip()))
        self.send_response(status)
        for key, value in response_headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()
        if self.command == "GET" and os.path.exists(race_file) and "receive-pack" in (parsed.path + "?" + parsed.query):
            with open(race_file, encoding="ascii") as source:
                race_ref, race_oid = source.read().strip().split(" ", 1)
            os.unlink(race_file)
            subprocess.run(["git", "--git-dir", root + "/org/repo.git", "update-ref", race_ref, race_oid], check=True)
            with open(marker, "w", encoding="ascii") as output:
                output.write(race_oid + "\n")
        if result.returncode != 0:
            print(result.stderr.decode("utf-8", "replace"), file=sys.stderr)

    def log_message(self, *_args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
context = __import__("ssl").SSLContext(__import__("ssl").PROTOCOL_TLS_SERVER)
context.load_cert_chain(os.environ["PERSONA_TEST_TLS_CERT"], os.environ["PERSONA_TEST_TLS_KEY"])
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_address[1], flush=True)
server.serve_forever()
