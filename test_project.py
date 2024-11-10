from unittest.mock import patch
import jwt
import time

from project import (
    get_all_users,
    get_user,
    authenticate_user,
    generate_token,
    User,
    SECRET_KEY,
    ALGORITHM,
)


def test_get_all_users():
    with patch("project.session") as mock_session:
        mock_user1 = User(id=1, email="user1@example.com", password="pass1")
        mock_user2 = User(id=2, email="user2@example.com", password="pass2")
        mock_session.query.return_value.all.return_value = [mock_user1, mock_user2]

        users = get_all_users()
        assert len(users) == 2
        assert users[0]["email"] == "user1@example.com"
        assert users[1]["email"] == "user2@example.com"


def test_get_user():
    with patch("project.session") as mock_session:
        mock_user = User(id=1, email="user@example.com", password="pass")
        mock_session.query.return_value.filter_by.return_value.first.return_value = (
            mock_user
        )

        user = get_user(1)
        assert user["id"] == 1
        assert user["email"] == "user@example.com"


def test_authenticate_user():
    with patch("project.session") as mock_session:
        mock_user = User(id=1, email="user@example.com", password="pass")
        mock_session.query.return_value.filter_by.return_value.first.return_value = (
            mock_user
        )

        user = authenticate_user("user@example.com", "pass")
        assert str(user.email) == "user@example.com"


def test_generate_token():
    email = "user@example.com"
    token = generate_token(email)
    assert isinstance(token, str)

    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["email"] == email
    assert payload["exp"] > time.time()
