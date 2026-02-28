MAX_POSIX_ID = 2**32-1


def is_valid_id(value: int) -> bool:
  return isinstance(value, int) and 0 <= value <= MAX_POSIX_ID
  