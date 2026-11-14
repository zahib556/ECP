"""Хранение паролей: PBKDF2-HMAC-SHA256, уникальная соль на пользователя, оценка сложности."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from typing import List, Tuple

ALGORITHM = "pbkdf2_sha256"
MIN_ITERATIONS = 200_000       # требование задания
ITERATIONS = 310_000           # значение по умолчанию
SALT_BYTES = 16
MIN_LENGTH = 8
MAX_LENGTH = 128

STRENGTH_LABELS = ("очень слабый", "слабый", "средний", "хороший", "надёжный")
_COMMON = {"password", "qwerty", "12345678", "123456789", "11111111", "iloveyou", "admin123",
           "qwertyui", "password1", "qwerty123", "1q2w3e4r", "00000000"}


def new_salt() -> str:
    return secrets.token_hex(SALT_BYTES)


def hash_password(password: str, salt: str, iterations: int = ITERATIONS) -> str:
    """Строка вида «pbkdf2_sha256$итерации$хэш_hex». Число итераций хранится вместе с хэшем."""
    if iterations < MIN_ITERATIONS:
        raise ValueError(f"число итераций PBKDF2 должно быть не меньше {MIN_ITERATIONS}")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations)
    return f"{ALGORITHM}${iterations}${digest.hex()}"


def verify_password(password: str, salt: str, stored: str) -> bool:
    try:
        algorithm, count, _ = stored.split("$")
        if algorithm != ALGORITHM or int(count) < MIN_ITERATIONS:
            return False
        expected = hash_password(password, salt, int(count))
        return hmac.compare_digest(expected.encode("ascii"), stored.encode("ascii"))
    except (ValueError, TypeError):  # UnicodeEncodeError - тоже ValueError
        return False


def strength(password: str) -> Tuple[int, str]:
    """Оценка сложности 0..4 и её название (для индикатора в окне регистрации)."""
    if not password:
        return 0, STRENGTH_LABELS[0]
    classes = sum(bool(re.search(p, password)) for p in (r"[a-zа-яё]", r"[A-ZА-ЯЁ]", r"\d", r"[^\w\s]|_"))
    score = 0
    if len(password) >= MIN_LENGTH:
        score += 1
    if len(password) >= 12:
        score += 1
    if classes >= 3:
        score += 1
    if classes >= 4 or len(password) >= 16:
        score += 1
    if password.lower() in _COMMON or len(set(password)) <= 3:
        score = 0
    elif len(password) < MIN_LENGTH:
        score = min(score, 1)
    return score, STRENGTH_LABELS[score]


def policy_problems(password: str) -> List[str]:
    """Нарушения политики паролей при регистрации (пустой список - пароль допустим)."""
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"пароль короче {MIN_LENGTH} символов")
    if len(password) > MAX_LENGTH:
        problems.append(f"пароль длиннее {MAX_LENGTH} символов")
    if password.lower() in _COMMON or (password and len(set(password)) <= 3):
        problems.append("пароль слишком простой")
    elif len(password) >= MIN_LENGTH and sum(bool(re.search(p, password)) for p in
                                              (r"[^\W\d_]", r"\d", r"[\W_]")) < 2:
        problems.append("добавьте цифры или другие символы к буквам")
    return problems
