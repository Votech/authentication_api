# JWT Authentication API Server

#### Description

This is my final project for the CS50P course. It's a simple API server that provides authentication and token-based authorization JWT (JSON Web Token). It is built with Python, utilizing several libraries, including sqlalchemy for database management. pywjt for generating and validating tokens, and http.server that comes from Python as a simple solution for handling HTTP requests. The server supports the creation of user accounts, authentication, and token validation.

### Features

- **User Creation**: Allows the creation of a new user account by providing an email and password.
- **Authentication**: Users can authenticate by sending their email and password. If successful, the server returns a JWT that can be used for subsequent requests.
- **Token Validation**: The server validates JWTs for protected endpoints to ensure that requests are made by authorized users.
- **SQLite Database**: User data is stored in a simple SQLite database (`users.db`), with tables for storing email and password information.

### Architecture

1. **SQLAlchemy**: Manages interactions with an SQLite database for storing user information.
2. SQLite is a little database that comes with Python. Its simplicity, lightweight nature, and the fact that the whole database is just a one file make it an ideal choice for this kind of side project.
3. **JWT**: Used for issuing authentication tokens to authenticated users. The token includes the user’s email and an expiration time.
4. **HTTP Server**: A basic HTTP server using Python’s `http.server` module that handles incoming HTTP requests.
5. **Error Handling**: Custom error handling for cases such as user not found, incorrect credentials, and invalid or expired tokens.

### File Structure

- **`project.py`**: Main server code that initializes the database, defines the HTTP request handling logic, user authentication, and token generation.
- test_project.py: Unit tests.
- **`users.db`**: SQLite database that stores user information (created automatically).
- **`README.md`**: Documentation of the project.

### Endpoints

1. **POST /user**: Creates a new user. Requires JSON with `email` and `password`.

   - Example:

     ```json
     { "email": "user@example.com", "password": "password123" }
     ```

2. **POST /token**: Authenticates a user and returns a JWT. Requires JSON with `email` and `password`.

   - Example:

     ```json
     { "email": "user@example.com", "password": "password123" }
     ```

3. **GET /users**: Returns a list of all users (requires valid token in Authorization header).
4. **GET /user/{id}**: Retrieves a user by ID (requires valid token in Authorization header).

### Design Decisions

- **Security**: Passwords are stored in plain text in this simplified version. In a real-world application, passwords should be hashed and salted using a library like `bcrypt`.
- **Token Expiry**: Tokens are set to expire after 10 minutes for security purposes, requiring users to re-authenticate periodically.
- **SQLAlchemy**: The project uses SQLAlchemy for ORM functionality, simplifying the management of the SQLite database.

### Running the Server

To run the server, execute the following command:

```bash
python project.py
```

The server will be available at <http://localhost:3456>

### Running the tests

```bash
pytest test_project.py
```

### Future Improvements

- Implement password hashing and salting for better security.
- Add user roles (e.g., admin, user) for more granular access control.
- Support for additional endpoints like user password update and deletion.

#### Video Demo: <https://youtu.be/X-EkqcJ6SKY>
