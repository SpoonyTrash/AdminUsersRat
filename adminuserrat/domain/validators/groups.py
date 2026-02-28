from typing import Any

def normalize_groups(raw_groups: Any) -> tuple[str, ...]:
  if isinstance(raw_groups, str):
    return tuple(g.strip() for g in raw_groups.split(",") if isinstance(g, str) and g.strip())
  if isinstance(raw_groups, (list, tuple, set)):
    return tuple(g.strip() for g in raw_groups if isinstance(g, str) and g.strip())
  return tuple()