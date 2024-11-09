from http.server import BaseHTTPRequestHandler, HTTPServer
import re

db = {"1": "Magda", "2": "Wojtek", "3": "Son Goku"}


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        match_user = re.match(r"^/user/(\d+)$", self.path)
        if match_user:
            user_id = match_user.group(1)
            try:
                user = db[user_id]
                response = f"User: {user}, id: {user_id}\n"
                self.send_response(200)
            except KeyError:
                response = f"User with id: {user_id} not found\n"
                self.send_response(404)

            self.send_header("Content-type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(response.encode("utf8"))
        else:
            # Handle non-matching paths
            self.send_response(404)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write("Not Found\n".encode("utf8"))


def run_server():
    port = 3456
    server_address = ("", port)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f"Server running on http://localhost:{port}")
    httpd.serve_forever()


def main():
    run_server()


if __name__ == "__main__":
    main()
