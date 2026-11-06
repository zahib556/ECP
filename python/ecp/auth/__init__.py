"""Аутентификация пользователей (практическая работа «Аутентификация пользователей»).

Вместо REST-маршрутов (разрешено заданием) используются модули:

    /register -> AuthService.register     /login -> AuthService.login
    /logout   -> AuthService.logout       /me    -> AuthService.me

Состав: passwords (PBKDF2), tokens (JWT HS256), device (отпечаток устройства),
store (SQLite), service (логика), session (токен только в памяти клиента).
"""
from .service import AuthError, AuthService, LoginResult, Registration, SessionExpired, UserInfo
from .session import ClientSession

__all__ = [
    "AuthError", "AuthService", "ClientSession", "LoginResult",
    "Registration", "SessionExpired", "UserInfo",
]
