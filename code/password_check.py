def check_password(user_input):
    SECRET_PASSWORD = "admin123"
    if len(user_input) != len(SECRET_PASSWORD):
        return False
    for u,c in zip(user_input, SECRET_PASSWORD):
        if u != c:
            return False
    return True
