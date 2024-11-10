import json
import re
import secrets
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
from sqlalchemy import create_engine, Column, Integer, String, exc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Generate a 256-bit (32-byte) secret key
SECRET_KEY = secrets.token_hex(32)
print(f"Generated secret key: {SECRET_KEY}")

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
    def __init__(self, message="User already exists."):
        self.message = message
        super().__init__(self.message)


class AuthenticationError(Exception):
    def __init__(self, message="Incorrect email or password."):
        self.message = message
        super().__init__(self.message)


class InvalidTokenError(Exception):
    def __init__(self, message="Invalid token."):
        self.message = message
        super().__init__(self.message)


class RequestHandler(BaseHTTPRequestHandler):
    def _send_response(
        self, response, status_code=200, content_type="application/json"
    ):
        self.send_response(status_code)
        self.send_header("Content-type", content_type)
        self.end_headers()
        self.wfile.write(response.encode("utf-8"))

    def _validate_token(self):
        auth_header = self.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise InvalidTokenError("Missing or invalid token")
        token = auth_header.split(" ")[1]
        email, _ = decode_token(token)
        return email

    def do_GET(self):
        try:
            self._validate_token()
        except InvalidTokenError as e:
            self._send_response(json.dumps({"error": str(e)}), 401)
            return

        if self.path == "/users":
            users = get_all_users()
            self._send_response(json.dumps(users))
        elif match_user := re.match(r"^/user/(\d+)$", self.path):
            user_id = match_user.group(1)
            try:
                user = get_user(int(user_id))
                self._send_response(json.dumps(user))
            except UserDoesntExistsError as e:
                self._send_response(json.dumps({"error": str(e)}), 404)
        else:
            self._send_response(json.dumps({"error": "Not Found"}), 404)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        try:
            data = json.loads(post_data)
        except json.JSONDecodeError:
            self._send_response(json.dumps({"error": "Invalid JSON format"}), 400)
            return

        if self.path == "/user":
            try:
                create_user(email=data["email"], password=data["password"])
                self._send_response(
                    json.dumps({"message": "User created successfully"}), 201
                )
            except KeyError:
                self._send_response(json.dumps({"error": "Invalid data"}), 400)
            except UserAlreadyExistsError as e:
                self._send_response(json.dumps({"error": str(e)}), 409)
        elif self.path == "/token":
            try:
                user = authenticate_user(email=data["email"], password=data["password"])
                token = generate_token(user.email)
                self._send_response(json.dumps({"token": token}))
            except KeyError:
                self._send_response(json.dumps({"error": "Invalid data"}), 400)
            except AuthenticationError as e:
                self._send_response(json.dumps({"error": str(e)}), 401)
        else:
            self._send_response(json.dumps({"error": "Not Found"}), 404)


def get_all_users():
    users = session.query(User).all()
    return [{"id": user.id, "email": user.email} for user in users]


def get_user(user_id: int):
    user = session.query(User).filter_by(id=user_id).first()
    if user:
        return {"id": user.id, "email": user.email, "password": user.password}
    raise UserDoesntExistsError()


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


def authenticate_user(**user):
    email = user["email"]
    password = user["password"]
    if user := session.query(User).filter_by(email=email).first():
        if user.password == password:
            return user
        else:
            raise AuthenticationError()
    else:
        raise AuthenticationError()


def generate_token(email):
    TOKEN_EXPIRES_IN_SECONDS = 10 * 60
    payload = {
        "email": email,
        "exp": time.time() + TOKEN_EXPIRES_IN_SECONDS,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token


def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["email"], payload["exp"]
    except jwt.ExpiredSignatureError:
        raise InvalidTokenError("Token has expired")
    except jwt.InvalidTokenError:
        raise InvalidTokenError("Invalid token")


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
