from dataclasses import dataclass, field, replace
from datetime import date, datetime
from pathlib import PurePosixPath
from typing import Any, Mapping

DEFAULT_SHELL = "/bin/bash"
SYSTEM_UID_THRESHOLD = 1000
CRITICAL_USERNAMES = {"root", "nobody", "daemon", "bin", "sys", "sync", "games", "man"}
DEFAULT_DELETE_PROTECTED_UID = 100
USERNAME_MAX_LENGTH = 32
MAX_POSIX_ID = 2**32-1
SENSITIVE_METADATA_KEYWORDS = ("shadow", "passwd", "password", "hash", "secret", "token", "raw")

@dataclass(frozen=True)
class User:
  username: str
  uid: int
  gid: int
  home: str
  shell: str
  groups: tuple[str, ...] = field(default_factory=tuple)
  primary_group: str | None = None
  gecos: str | None = None
  locked: bool = False
  lock_status: str | None = None
  login_allowed: bool = True
  sudo_enabled: bool = False
  account_expire_date: date | None = None
  inactive_days: int | None = None
  password_last_changed: date | None = None
  pass_max_days: int | None = None
  force_password_change: bool = False
  explicit_system_account: bool | None = None
  metadata: Mapping[str, Any] = field(default_factory=dict)

  def __post_init__(self) -> None:
    normalized = self.normalize()
    object.__setattr__(self, "username", normalized["username"])
    object.__setattr__(self, "home", normalized["home"])
    object.__setattr__(self, "shell", normalized["shell"])
    object.__setattr__(self, "groups", tuple(dict.fromkeys(normalized["groups"])))
    object.__setattr__(self, "metadata", dict(self.metadata or {}))
    self.validate()

  @classmethod
  def create(
    cls,
    username: str,
    uid: int,
    gid: int,
    home: str | None = None,
    shell: str | None = None,
    groups: list[str] | tuple[str, ...] | None = None,
    **kwargs: Any,
  ) -> "User":
    normalized_username = username.strip().lower()
    resolved_home = home or f"/home/{normalized_username}"
    resolved_shell = shell or DEFAULT_SHELL
    explicit_system_account = kwargs.pop("explicit_system_account", None)

    if explicit_system_account is None:
      explicit_system_account = uid <  SYSTEM_UID_THRESHOLD

    return cls(
      username=normalized_username,
      uid=uid,
      gid=gid,
      home=resolved_home,
      shell=resolved_shell,
      groups=tuple(groups or ()),
      explicit_system_account=explicit_system_account,
      **kwargs,
    )

  @classmethod
  def from_passwd_record(cls, record: Mapping[str, Any]) -> "User":
    return cls.create(
      username=str(record.get("username") or record.get("name") or ""),
      uid=int(record.get("uid", -1)),
      gid=int(record.get("gid", -1)),
      home=record.get("home") or record.get("home_dir"),
      shell=record.get("shell"),
      gecos=record.get("gecos"),
      metadata={"source": "passwd", "raw": dict(record)}
    )
  
  @classmethod
  def from_dict(cls, data: Mapping[str, Any]) -> "User":
    payload = dict(data)
    payload["groups"] = cls._normalize_groups(payload.get("groups")or [])

    for id_field in ("uid", "gid"):
      raw = payload.get(id_field)
      if raw is not None:
        payload[id_field] = int(raw)

    for date_field in ("account_expire_date", "password_last_changed"):
      raw = payload.get(date_field)
      
      if isinstance(raw, str) and raw:
        payload[date_field] = cls._parse_date(raw)
    
    return cls(**payload)
  
  def with_shadow_info(self, shadow_info: Mapping[str, Any]) -> "User":
    return replace(
      self,
      locked=bool(shadow_info.get("locked", self.locked)),
      lock_status=shadow_info.get("lock_status", self.lock_status),
      account_expire_date= self._parse_date_maybe(shadow_info.get("account_expire_date"), self.account_expire_date),
      password_last_changed=self._parse_date_maybe(shadow_info.get("password_last_changed"), self.password_last_changed),
      pass_max_days=shadow_info.get("pass_max_days", self.pass_max_days),
      inactive_days=shadow_info.get("inactive_days", self.inactive_days),
      force_password_change=bool(shadow_info.get("force_password_change", self.force_password_change)),
      metadata={**self.metadata, "shadow": dict(shadow_info)}
    )
  
  def with_groups(self, groups: list[str], primary_gid: int | None = None) -> "User":
    return replace(self, groups=self._normalize_groups(groups), gid=primary_gid if primary_gid is not None else self.gid)
  
  def normalize(self) -> dict[str, Any]:
    username = self.username.strip().lower()
    groups = self._normalize_groups(self.groups)
    home_path = str(PurePosixPath("/" + self.home.lstrip("/"))) if self.home else f"/home/{username}"
    shell = self.shell.strip() if self.shell else DEFAULT_SHELL

    return {"username": username, "home": home_path, "shell": shell, "groups": groups}

  def validate(self) -> None:
    if not self.username or not self._is_valid_username(self.username):
      raise ValueError(f"Invalid username: {self.username!r}")
    if not self._is_valid_id(self.uid):
      raise ValueError(f"invalid uid: {self.uid}")
    if not self._is_valid_id(self.gid):
      raise ValueError(f"invalid gid: {self.gid}")
    if not self.home.startswith("/"):
      raise ValueError("home must be an absolute path.")
    if not self.shell.startswith("/"):
      raise ValueError("shell must be an absolute path")
    if self.pass_max_days is not None and self.pass_max_days < 0:
      raise ValueError("pass_max_days cannot be negative.")
    if self.inactive_days is not None and self.inactive_days < 0:
      raise ValueError("inactive_days cannot be negative")
  
  def is_locked(self) -> bool:
    return self.locked or (self.lock_status or "").lower() in {"locked", "auto_locked", "manual_locked"}

  def is_expired(self, on_date: date | None = None) -> bool:
    if not self.account_expire_date:
      return False
    return self.account_expire_date <= (on_date or date.today())

  def password_is_expired(self, on_date: date | None = None) -> bool:
    if self.force_password_change:
      return True
    if not self.password_last_changed or self.pass_max_days is None:
      return False
    check_date = on_date or date.today()
    return (check_date - self.password_last_changed).days >= self.pass_max_days

  def requires_password_change(self) -> bool:
    return self.force_password_change
  
  def is_active(self, on_date: date | None = None) -> bool:
    return self.login_allowed and not self.is_locked() and not self.is_expired(on_date)
  
  def has_sudo(self) -> bool:
    groups_lower = {group.lower() for group in self.groups}
    return self.sudo_enabled or bool({"sudo", "wheel"} & groups_lower)

  def is_system_account(self, uid_threshold: int = SYSTEM_UID_THRESHOLD) -> bool:
    if self.explicit_system_account is not None:
      return self.explicit_system_account
    return self.uid < uid_threshold
  
  def can_be_deleted(self) -> tuple[bool, str | None]:
    if self.username in CRITICAL_USERNAMES:
      return False, f"{self.username} is a protected account"
    if self.uid < DEFAULT_DELETE_PROTECTED_UID:
      return False, f"uid {self.uid} is below protected threshold"
    return True, None
  
  def can_be_locked(self) -> tuple[bool, str | None]:
    if self.username == "root":
      return False, "root account cannot be locked without override"
    if self.username in CRITICAL_USERNAMES and self.uid < SYSTEM_UID_THRESHOLD:
      return False, f"{self.username} is a critical system account"
    return True, None
  
  def diff(self, other_user: "User") -> dict[str, dict[str, Any]]:
    changes: dict[str, Any] = {}
    tracked_fields = (
      "home",
      "shell",
      "groups",
      "locked",
      "login_allowed",
      "sudo_enabled",
      "account_expire_date",
      "inactive_days",
      "password_last_changed",
      "pass_max_days",
      "force_password_change"
    )
    for field_name in tracked_fields:
      old = getattr(self, field_name)
      new = getattr(other_user, field_name)
      if old != new:
        changes[field_name] = {"before": old, "after": new}
    
    return changes

  def apply_patch(self, patch: Mapping[str, Any]) -> "User":
    allowed = {
      "home",
      "shell",
      "groups",
      "locked",
      "login_allowed",
      "sudo_enabled",
      "account_expire_date",
      "inactive_days",
      "password_last_changed",
      "pass_max_days",
      "force_password_change",
      "metadata"
    }
    invalid_keys = [k for k in patch if k not in allowed]
    if invalid_keys:
      raise ValueError(f"Unsupported patch fields: {', '.join(invalid_keys)}")
    
    normalized_patch = dict(patch)
    if "groups" in normalized_patch:
      normalized_patch["groups"] = self._normalize_groups(normalized_patch["groups"])
    if "account_expire_date" in normalized_patch:
      normalized_patch["account_expire_date"] = self._parse_date_maybe(
        normalized_patch["account_expire_date"], self.account_expire_date
      )
    if "password_last_changed" in normalized_patch:
      normalized_patch["password_last_changed"] = self._parse_date_maybe(
        normalized_patch["password_last_changed"], self.password_last_changed
      )

    return replace(self, **normalized_patch)
  
  def effective_groups(self) -> list[str]:
    all_groups = set(self.groups)
    if self.primary_group:
      all_groups.add(self.primary_group)
    return sorted(all_groups)
  
  def to_dict(self, include_private: bool = False) -> dict[str, Any]:
    data = {
      "username": self.username,
      "uid": self.uid,
      "gid": self.gid,
      "home": self.home,
      "shell": self.shell,
      "groups": list(self.groups),
      "primary_group": self.primary_group,
      "gecos": self.gecos,
      "locked": self.is_locked(),
      "login_allowed": self.login_allowed,
      "sudo_enabled": self.sudo_enabled,
      "has_sudo": self.has_sudo(),
      "system_account": self.is_system_account(),
      "account_expire_date": self.account_expire_date.isoformat() if self.account_expire_date else None,
      "password_last_changed": self.password_last_changed.isoformat() if self.password_last_changed else None,
      "pass_max_days": self.pass_max_days,
      "inactive_days": self.inactive_days,
      "force_password_change": self.force_password_change
    }

    if include_private:
      data["metadata"] = self._sanitize_metadata(self.metadata)
      data["lock_status"] = self.lock_status
      data["explicit_system_account"] = self.explicit_system_account
    return data
  
  def to_report_row(self) -> dict[str, Any]:
    return {
      "username": self.username,
      "uid": self.uid,
      "home": self.home,
      "shell": self.shell,
      "locked": self.is_locked(),
      "expired": self.is_expired(),
      "active": self.is_active(),
      "sudo": self.has_sudo(),
      "groups_count": len(self.effective_groups())
    }
  
  def summary(self) -> dict[str, Any]:
    return{
      "username": self.username,
      "uid": self.uid,
      "active": self.is_active(),
      "locked": self.is_locked(),
      "sudo": self.has_sudo()
    }
  
  def attach_policy(self, policy: Any) -> "User":
    return replace(self, metadata={**self.metadata, "policy": policy})

  def effective_policy(self) -> Any:
    return self.metadata.get("policy")
  
  def display_name(self) -> str:
    return self.gecos.strip() if self.gecos and self.gecos.strip() else self.username

  def __str__(self) -> str:
    return f"User(username={self.username}, uid={self.uid}, active={self.is_active()})"

  def __repr__(self) -> str:
    return(
      "User(" \
      f"username={self.username!r}, uid={self.uid}, gid={self.gid}, "
      f"home={self.home!r}, shell={self.shell!r}, locked={self.is_locked()}, sudo={self.has_sudo()}"
      ")"
    )

  @staticmethod
  def _is_valid_username(username: str) -> bool:
    if not username:
      return False
    if len(username) > USERNAME_MAX_LENGTH:
      return False
    
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._-")
    return username[0].isalnum() and all(ch in allowed for ch in username)

  @staticmethod
  def _is_valid_id(value: int) -> bool:
    return isinstance(value, int) and 0 <= value <= MAX_POSIX_ID

  @staticmethod
  def _parse_date(raw: str) -> date:
    try:
      return datetime.fromisoformat(raw).date()
    except ValueError:
      pass
      
    supported_formats = ("%Y/%m/%d", "%d/%m/%Y", "%d-%m-%Y")
    for fmt in supported_formats:
      try:
        return datetime.strptime(raw, fmt).date()
      except ValueError:
        continue

    raise ValueError(f"Unsopprted date format: {raw!r}")
  
  @staticmethod
  def _parse_date_maybe(raw: Any, fallback: date | None = None) -> date | None:
    if raw is None:
      return fallback
    if isinstance(raw, date):
      return raw
    if isinstance(raw, str) and raw:
      return User._parse_date(raw)
    return fallback

  @staticmethod
  def _normalize_groups(raw_groups: Any) -> tuple[str, ...]:
    if isinstance(raw_groups, str):
      return tuple(g.strip() for g in raw_groups.split(",") if isinstance(g, str) and g.strip())
    if isinstance(raw_groups, (list, tuple, set)):
      return tuple(g.strip() for g in raw_groups if isinstance(g, str) and g.strip())
    return tuple()
  
  @staticmethod
  def _sanitize_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in metadata.items():
      normalized_key = str(key).lower()
      if any(keyword in normalized_key for keyword in SENSITIVE_METADATA_KEYWORDS):
        sanitized[str(key)] = "[redacted]"
      else:
        sanitized[str(key)] = value
    return sanitized