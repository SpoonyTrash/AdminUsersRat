from datetime import date, datetime

_SUPPORTED_DATE_FORMATS = ("%Y/%m/%d", "%d/%m/%Y", "%d-%m-%Y")


def parse_date(raw: str) -> date:
  try:
    return datetime.fromisoformat(raw).date()
  except ValueError:
    pass
    
  for fmt in _SUPPORTED_DATE_FORMATS:
    try:
      return datetime.strptime(raw, fmt).date()
    except ValueError:
      continue

  raise ValueError(f"Unsupprted date format: {raw!r}")

def parse_date_maybe(raw: object, fallback: date | None = None) -> date | None:
  if raw is None:
    return fallback
  if isinstance(raw, date):
    return raw
  if isinstance(raw, str) and raw:
    return parse_date(raw)
  return fallback