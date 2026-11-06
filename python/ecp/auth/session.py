"""Сессия клиента. Токен хранится только в оперативной памяти: ни в файле, ни в журнале."""
from __future__ import annotations

from typing import Optional


class ClientSession:
    __slots__ = ("_token", "login", "expires_at")

    def __init__(self) -> None:
        self._token: Optional[str] = None
        self.login: Optional[str] = None
        self.expires_at: Optional[str] = None

    def start(self, token: str, login: str, expires_at: str) -> None:
        self._token, self.login, self.expires_at = token, login, expires_at

    @property
    def token(self) -> Optional[str]:
        return self._token

    @property
    def active(self) -> bool:
        return self._token is not None

    def clear(self) -> None:
        self._token = self.login = self.expires_at = None

    def __repr__(self) -> str:  # токен в repr не попадает
        return f"ClientSession(login={self.login!r}, active={self.active})"
