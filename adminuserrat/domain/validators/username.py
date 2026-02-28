USERNAME_MAX_LENGTH = 32
_ALLOWED_USERNAME_CHARS= set("abcdefghijklmnopqrstuvwxyz0123456789._-")



def is_valid_username(username: str) -> bool:
  if not username:
    return False
  if len(username) > USERNAME_MAX_LENGTH:
    return False
  
  return username[0].isalnum() and all(ch in _ALLOWED_USERNAME_CHARS for ch in username)