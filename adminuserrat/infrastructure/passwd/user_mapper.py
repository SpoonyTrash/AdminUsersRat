from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any, Mapping

from adminuserrat.domain.models.user import User

EPOCH_DATE = date(1970, 1, 1)


@dataclass(frozen=True)
class PasswdUserMapper:

  default_source: str = "passwd"

  def from_passwd_record(self, record: Mapping[str, Any]) -> User:
    return User.create(
      username=str(record.get("username") or record.get("name") or ""),
      uid=self._to_int(record.get("uid"), fallback=-1),
      gid=self._to_int(record.get("gid"), fallback=-1),
      home=self._to_optional_str(record.get("home") or record.get("home_dir")),
      shell=self._to_optional_str(record.get("shell")),
      gecos=self._to_optional_str(record.get("gecos")),
      metadata={"source": self.default_source},
    )

  def with_shadow_record(self, user: User, shadow_record: Mapping[str, Any]) -> User:
    return user.apply_patch(
      {
        "locked": self._to_bool(shadow_record.get("locked"), fallback=user.locked),
        "lock_status": self._to_optional_str(shadow_record.get("lock_status")) or user.lock_status,
        "account_expire_date": self._to_date(shadow_record.get("account_expire_date"), fallback=user.account_expire_date),
        "password_last_changed": self._to_date(
          shadow_record.get("password_last_changed"), fallback=user.password_last_changed
        ),
        "pass_max_days": self._to_optional_int(shadow_record.get("pass_max_days"), fallback=user.pass_max_days),
        "inactive_days": self._to_optional_int(shadow_record.get("inactive_days"), fallback=user.inactive_days),
        "force_password_change": self._to_bool(
          shadow_record.get("force_password_change"), fallback=user.force_password_change
        ),
        "metadata": self._merge_source_metadata(user.metadata),
      }
    )

  def _merge_source_metadata(self, metadata: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(metadata)
    merged.setdefault("source", self.default_source)
    return merged

  @staticmethod
  def _to_optional_str(raw: Any) -> str | None:
    if raw is None:
      return None
    value = str(raw).strip()
    return value or None

  @staticmethod
  def _to_int(raw: Any, fallback: int) -> int:
    try:
      return int(raw)
    except (TypeError, ValueError):
      return fallback

  @staticmethod
  def _to_optional_int(raw: Any, fallback: int | None = None) -> int | None:
    if raw is None or raw == "":
      return fallback
    try:
      return int(raw)
    except (TypeError, ValueError):
      return fallback

  @staticmethod
  def _to_bool(raw: Any, fallback: bool = False) -> bool:
    if raw is None:
      return fallback
    if isinstance(raw, bool):
      return raw
    if isinstance(raw, str):
      return raw.strip().lower() in {"1", "true", "yes", "y", "locked"}
    return bool(raw)

  @classmethod
  def _to_date(cls, raw: Any, fallback: date | None = None) -> date | None:
    if raw is None or raw == "":
      return fallback
    if isinstance(raw, date):
      return raw
    if isinstance(raw, int):
      return cls._from_shadow_days(raw)
    if isinstance(raw, str):
      stripped = raw.strip()
      if not stripped:
        return fallback
      if stripped.lstrip("-").isdigit():
        return cls._from_shadow_days(int(stripped))
      try:
        return date.fromisoformat(stripped)
      except ValueError:
        return fallback
    return fallback

  @staticmethod
  def _from_shadow_days(days: int) -> date | None:
    if days < 0:
      return None
    return EPOCH_DATE + timedelta(days=days)