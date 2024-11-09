from http.server import BaseHTTPRequestHandler, HTTPServer
import re
import json
from sqlalchemy import create_engine, Column, Integer, String, exc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Initialize SQLAlchemy
engine = create_engine("sqlite:///users.db")
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)


Base.metadata.create_all(engine)


class UserDoesntExistsError(Exception):
    def __init__(self, message=""):
        self.message = message
        super().__init__(self.message)


class UserAlreadyExistsError(Exception):
    def __init__(self, message=""):
        self.message = message
        super().__init__(self.message)


class RequestHandler(BaseHTTPRequestHandler):
    def _handle_send_response(self, response):
        self.send_header("Content-type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(response.encode("utf8"))

    def _handle_non_matching_paths(self):
        self.send_response(404)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write("Not Found\n".encode("utf8"))

    def do_GET(self):
        # Get all users
        if self.path == "/users":
            users = get_all_users()
            response = json.dumps(users)
            self.send_response(200)
            self._handle_send_response(response)
        # Get user by id
        elif match_user := re.match(r"^/user/(\d+)$", self.path):
            user_id = match_user.group(1)
            try:
                user = get_user(int(user_id))
                response = f"User: {user}, id: {user_id}\n"
                self.send_response(200)
            except UserDoesntExistsError:
                response = f"User with id: {user_id} not found\n"
                self.send_response(404)
            self._handle_send_response(response)
        else:
            # Handle non-matching paths
            self._handle_non_matching_paths()

    def do_POST(self):
        # Handle POST request to create a new user
        if self.path == "/user":
            # Get the content length to read the exact amount of data
            # Otherwise the server will not know how much data to read
            # Witch results in infinite wait for more data
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data)
                email = data["email"]
                password = data["password"]
                create_user(email=email, password=password)
                response = f"User {email} created sucessfully.\n"
                self.send_response(201)
            except KeyError:
                response = "Invalid data.\n"
                self.send_response(400)
            except UserAlreadyExistsError:
                response = "User already exists.\n"
                self.send_response(409)
            except json.JSONDecodeError:
                response = "Invalid JSON format.\n"
                self.send_response(400)

            self._handle_send_response(response)
        else:
            self._handle_non_matching_paths()


def create_user(**user):
    email = user["email"]
    password = user["password"]
    new_user = User(email=email, password=password)
    try:
        session.add(new_user)
        session.commit()
    except exc.IntegrityError:
        session.rollback()
        raise UserAlreadyExistsError()


def get_user(user_id: int):
    user = session.query(User).filter_by(id=user_id).first()
    if user:
        return {"id": user.id, "email": user.email, "password": user.password}
    raise UserDoesntExistsError()


def get_all_users():
    users = session.query(User).all()
    return [{"id": user.id, "email": user.email} for user in users]


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
