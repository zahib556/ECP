"""Контекст приложения: конфигурация + журнал событий + операции управления конфигурацией.

Единая точка запуска: AppContext.start(). Все изменения конфигурационного файла идут через
методы контекста и фиксируются в журнале (создание, изменение, сброс, копирование, правка вне приложения).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

from . import config as cfgmod
from . import service
from .audit import AuditLog
from .auth import AuthError, AuthService, ClientSession, SessionExpired
from .auth.store import Database
from .auth import device as devmod
from .config import Config
from .errors import EcpError
from .version import VERSION


def build_audit(cfg: Config, **kwargs) -> AuditLog:
    return AuditLog(
        Path(cfg.logging.log_path),
        cfg.logging.log_format,
        cfgmod.parse_size(cfg.logging.max_file_size),
        cfgmod.parse_period(cfg.logging.cleanup_period),
        **kwargs,
    )


class AppContext:
    def __init__(self, config_path: Path, state_path: Path, config: Config, audit: AuditLog,
                 problems: List[str]) -> None:
        self.config_path = Path(config_path)
        self.state_path = Path(state_path)
        self.config = config
        self.audit = audit
        self.problems = problems
        self.auth: Optional[AuthService] = None       # включается enable_auth()
        self.session = ClientSession()                # токен только в памяти
        self.device_id_provider: Callable[[], str] = devmod.current_device_id
        self.on_session_lost: Optional[Callable[[str], None]] = None
        self._saved_audit_user: Optional[str] = None
        self._own_db: Optional[Database] = None       # update_audit, если аутентификация не включена

    # ------------------------------------------------------------ запуск и завершение
    @classmethod
    def start(cls, config_path: Optional[Path] = None, state_path: Optional[Path] = None,
              require_auth: bool = False, device_id: Optional[str] = None,
              **audit_kwargs) -> "AppContext":
        path = Path(config_path) if config_path else cfgmod.default_config_path()
        state = Path(state_path) if state_path else path.with_name(cfgmod.STATE_NAME)
        try:
            result = cfgmod.load(path)
            config, problems, created = result.config, result.problems, result.created
        except EcpError as e:  # конфигурацию не удалось даже создать: работаем на значениях по умолчанию
            config, problems, created = cfgmod.default_config(path.parent), [str(e)], False
        audit = build_audit(config, **audit_kwargs)
        ctx = cls(path, state, config, audit, problems)
        service.set_audit(audit)

        audit.info("ecp.app", f"Запуск приложения, версия {VERSION}")
        if created:
            audit.log("ecp.config", "Создан файл конфигурации со значениями по умолчанию",
                      action="create", obj=str(path))
        for problem in problems:
            audit.log("ecp.config", f"Конфигурация: {problem}", level="error", status="failure",
                      action="access", obj=str(path))
        ctx._detect_external_change()
        audit.info("ecp.config", "Конфигурация загружена", action="access", obj=str(path))
        if device_id is not None:
            ctx.device_id_provider = lambda: device_id
        if require_auth:
            try:
                ctx.enable_auth()
            except EcpError:  # база пользователей недоступна: не оставляем полузапущенный контекст
                ctx.shutdown()
                raise
        ctx.ingest_update_result()
        return ctx

    def shutdown(self) -> None:
        if self._own_db is not None:
            self._own_db.close()
            self._own_db = None
        if self.auth is not None:
            try:
                self.logout()
            except EcpError:
                pass
            self.auth.close()
            self.auth = None
            service.set_access_guard(None)
        self.audit.info("ecp.app", "Завершение работы приложения")
        service.set_audit(None)

    # ------------------------------------------------------------ аутентификация
    def enable_auth(self) -> None:
        """Включает обязательный вход: операции с файлами и конфигурацией требуют сессии."""
        self.auth = AuthService(self.state_path.with_name("users.db"), self.state_path.with_name("auth.key"),
                                audit=self.audit)
        service.set_access_guard(self._check_access)

    @property
    def auth_required(self) -> bool:
        return self.auth is not None

    @property
    def logged_in(self) -> bool:
        return self.session.active

    def register(self, login: str, password: str, confirm: str) -> str:
        """Регистрация. Возвращает одноразовый код сброса привязки устройства (показать один раз)."""
        auth = self._auth()
        if password != confirm:
            raise AuthError("Ошибка: пароль и подтверждение не совпадают")
        return auth.register(login, password, self.device_id_provider()).reset_code

    def login(self, login: str, password: str) -> str:
        auth = self._auth()
        result = auth.login(login, password, self.device_id_provider())
        self.session.start(result.token, result.login, result.expires_at)
        self._saved_audit_user = self.audit.user
        self.audit.user = result.login
        return result.login

    def logout(self) -> None:
        """Завершение сессии: /logout на стороне сервиса и очистка токена в памяти."""
        token = self.session.token
        self._end_session()
        if token and self.auth is not None:
            try:
                self.auth.logout(token)
            except AuthError:
                pass  # токен уже недействителен - локально сессия всё равно закрыта

    def reset_device(self, login: str, password: str, code: str) -> str:
        return self._auth().reset_device(login, password, code)

    def _auth(self) -> AuthService:
        if self.auth is None:
            raise AuthError("Ошибка: аутентификация не включена")
        return self.auth

    def _end_session(self) -> None:
        if self.session.active and self._saved_audit_user is not None:
            self.audit.user = self._saved_audit_user
        self._saved_audit_user = None
        self.session.clear()

    def require_access(self) -> None:
        """Явная проверка права на действие (для модулей вне service._op, например обновления)."""
        self._check_access()

    def check_session(self) -> None:
        """Периодическая проверка сессии из интерфейса; при истечении вызывает on_session_lost."""
        self._check_access()

    def _check_access(self) -> None:
        """Проверка перед каждой защищённой операцией: вход выполнен, токен действителен, устройство то же."""
        if self.auth is None:
            return
        token = self.session.token
        if token is None:
            self.audit.log("ecp.auth", "Отказ в доступе: вход не выполнен", level="warning", status="failure",
                           action="access")
            raise AuthError("Ошибка: требуется вход в систему")
        try:
            self.auth.me(token, self.device_id_provider())
        except SessionExpired as e:
            self._end_session()
            if self.on_session_lost is not None:
                self.on_session_lost(str(e))
            raise
        except AuthError:
            self._end_session()
            if self.on_session_lost is not None:
                self.on_session_lost("Доступ закрыт, выполните вход заново")
            raise

    # ------------------------------------------------------------ контроль правок вне приложения
    def _config_hash(self) -> str:
        try:
            return cfgmod.hash_file(self.config_path)
        except OSError:
            return ""

    def _remember_config_hash(self) -> None:
        state = cfgmod.load_state(self.state_path)
        state["config_hash"] = self._config_hash()
        cfgmod.save_state(self.state_path, state)

    def _detect_external_change(self) -> None:
        known = cfgmod.load_state(self.state_path).get("config_hash")
        current = self._config_hash()
        if known and current and known != current:
            self.audit.log("ecp.config", "Файл конфигурации изменён вне приложения (хэш не совпал с прошлым запуском)",
                           level="warning", status="success", action="modify", obj=str(self.config_path))
        self._remember_config_hash()

    # ------------------------------------------------------------ управление конфигурацией
    def save_config(self, new: Config, note: str = "Изменена конфигурация") -> bool:
        """Сохранение настроек. Возвращает False, если изменений нет."""
        self._check_access()
        problems = cfgmod.validate(new)
        if problems:
            text = "; ".join(problems)
            self.audit.log("ecp.config", f"Отклонено изменение конфигурации: {text}", level="error",
                           status="failure", action="modify", obj=str(self.config_path))
            raise EcpError("Ошибка: неверная конфигурация: " + text)
        changes = cfgmod.diff(self.config, new)
        if not changes:
            return False
        try:
            cfgmod.save(self.config_path, new)
        except EcpError as e:
            self.audit.log("ecp.config", str(e), level="error", status="failure", action="modify",
                           obj=str(self.config_path))
            raise
        old_log = self.config.logging
        self.config = new
        self._remember_config_hash()
        self.audit.log("ecp.config", f"{note}: " + "; ".join(changes), action="modify",
                       obj=str(self.config_path))
        if old_log != new.logging:
            self.audit.reconfigure(Path(new.logging.log_path), new.logging.log_format,
                                   cfgmod.parse_size(new.logging.max_file_size),
                                   cfgmod.parse_period(new.logging.cleanup_period))
            self.audit.info("ecp.audit", f"Параметры журнала изменены, запись продолжена в «{new.logging.log_path}»",
                            action="modify", obj=new.logging.log_path)
        return True

    def reset_config(self) -> bool:
        self._check_access()
        return self.save_config(cfgmod.default_config(self.config_path.parent),
                                note="Конфигурация сброшена к значениям по умолчанию")

    def export_config(self, dst: Path) -> None:
        self._check_access()
        try:
            cfgmod.export_config(self.config_path, dst)
        except EcpError as e:
            self.audit.log("ecp.config", str(e), level="error", status="failure", action="copy",
                           obj=str(dst))
            raise
        self.audit.log("ecp.config", f"Конфигурация экспортирована в «{Path(dst).name}»",
                       action="copy", obj=str(dst))

    def import_config(self, src: Path) -> bool:
        self._check_access()
        try:
            new = cfgmod.read_strict(src)
        except EcpError as e:
            self.audit.log("ecp.config", f"Импорт конфигурации из «{Path(src).name}» отклонён: {e}",
                           level="error", status="failure", action="copy", obj=str(src))
            raise
        return self.save_config(new, note=f"Конфигурация импортирована из «{Path(src).name}»")

    # ------------------------------------------------------------ обновление ПО
    UPDATE_STATUSES = ("verified", "downloaded", "installed", "failed", "rolled_back", "sbom_mismatch")

    @property
    def update_db(self) -> Database:
        """Локальная база с таблицей update_audit (общая с пользователями, если вход включён)."""
        if self.auth is not None:
            return self.auth.database
        if self._own_db is None:
            self._own_db = Database(self.state_path.with_name("users.db"))
        return self._own_db

    def record_update(self, status: str, from_version: str, to_version: str, detail: str = "") -> None:
        """Запись об обновлении: update_audit (SQLite) и журнал событий (источник ecp.update)."""
        if status not in self.UPDATE_STATUSES:
            raise ValueError(f"недопустимый статус обновления: {status}")
        user_id = None
        if self.auth is not None and self.session.login:
            row = self.auth.database.get_user(self.session.login)
            user_id = row.id if row else None
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            self.update_db.add_update_audit(user_id, self.device_id_provider(), from_version, to_version, status,
                                            self.audit.source_ip, now)
        except Exception as e:  # noqa: BLE001 - сбой базы не должен скрывать результат обновления
            self.audit.log("ecp.update", f"Не удалось записать update_audit: {e}", level="error", status="failure",
                           action="modify")
        ok = status in ("verified", "downloaded", "installed")
        level = "info" if ok else ("warning" if status == "rolled_back" else "error")
        text = f"Обновление {from_version} -> {to_version or '?'}: {status}" + (f" ({detail})" if detail and not ok else "")
        self.audit.log("ecp.update", text, level=level, status="success" if ok else "failure",
                       action="modify", obj=to_version)

    def make_updater(self, app_dir: Optional[Path] = None, current_version: Optional[str] = None,
                     public_key: Optional[bytes] = None, **kwargs):
        """Updater, привязанный к этому контексту: журнал, update_audit и проверка входа."""
        from .update import Updater, runtime
        folder = Path(app_dir) if app_dir else runtime.app_dir()
        kwargs.setdefault("entry_files", runtime.entry_files() if app_dir is None else ())
        return Updater(folder, current_version or VERSION, public_key, recorder=self.record_update,
                       guard=self.require_access, **kwargs)

    @property
    def update_result_path(self) -> Path:
        return self.state_path.with_name("update_result.json")

    def ingest_update_result(self) -> None:
        """Итог установки, записанный отдельным процессом (installed / rolled_back / failed), - в update_audit."""
        path = self.update_result_path
        if not path.is_file():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            status = data["status"]
            if status not in self.UPDATE_STATUSES:
                raise ValueError(status)
            self.record_update(status, str(data.get("from_version", ""))[:32], str(data.get("to_version", ""))[:32],
                               str(data.get("error", ""))[:300])
        except (OSError, ValueError, KeyError, TypeError):
            self.audit.log("ecp.update", "Файл результата обновления повреждён и проигнорирован", level="warning",
                           status="failure", action="access", obj=str(path))
        finally:
            try:
                path.unlink()
            except OSError:
                pass
