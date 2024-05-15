from werkzeug.security import generate_password_hash, check_password_hash
from db import Database


class PasswordAuth:
    def __init__(self) -> None:
        self.conn = Database.getconnection()

    def register(self, username: str, password: str) -> bool:
        print(f"Registering the user {username}")
        cur = self.conn.cursor()
        query = """
                SELECT username FROM User WHERE username = ?
                """
        cur.execute(query,(username,))
        retrieved_user = cur.fetchone()
        if retrieved_user:
            print("User already registered")
            return False
        
        if type(username) != str or type(password) != str:
            print("Registration failed")
            return False
        
        cur = self.conn.cursor()
        query = """
                INSERT INTO User (username, pass) VALUES(?,?);
                """
        cur.execute(query,(username,generate_password_hash(password)))
        self.conn.commit()
        print("Registration successful")
        return True


    def authenticate(self, username: str, password: str) -> bool:
        print(f"Authenticating the user {username}")
        cur = self.conn.cursor()
        query = """
                SELECT pass FROM User WHERE username = ?
                """
        cur.execute(query,(username,))
        retrieved_pass = cur.fetchone()
        if not retrieved_pass:
            return False
        result = check_password_hash(retrieved_pass[0], password)
        if result:
            print("Authentication successful")
        else:
            print("Authentication failed")
        return result
        # return check_password_hash(password_dict[username], password)


if __name__ == '__main__':
    name = 'aboeladahim2'
    password = '@roufa123456789ayman'

    auth = PasswordAuth()

    print("Status:", auth.register(name, password))
    if auth.authenticate(name, '@roufa123456789ayman'):
        print('Login Successful')
    else:
        print('Login Failed')

    if auth.authenticate(name, '@roufa123456789yman'):
        print('Login Successful')
    else:
        print('Login Failed')
