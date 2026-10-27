import http.server
import socketserver
import json

PORT = 9000

class MockHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        payload = {
            "status": "ok",
            "service": "backend-payload",
            "message": "Traversed Rathole reverse tunnel successfully!",
            "client_address": self.client_address[0]
        }
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def log_message(self, format, *args):
        print(f"[MockBackend] {self.address_string()} - {format % args}", flush=True)

with socketserver.TCPServer(("0.0.0.0", PORT), MockHandler) as httpd:
    print(f"[MockBackend] Listening on port {PORT}...", flush=True)
    httpd.serve_forever()
