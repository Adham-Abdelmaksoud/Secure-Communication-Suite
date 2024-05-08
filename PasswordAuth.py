from werkzeug.security import generate_password_hash, check_password_hash

password_dict = dict()

class PasswordAuth:
    @staticmethod
    def register(username: str, password: str) -> bool:
        if type(username) != str or type(password) != str:
            return False
        password_dict[username] = generate_password_hash(password)
        return True

    @staticmethod
    def authenticate(username: str, password: str) -> bool:
        return check_password_hash(password_dict[username], password)
    


if __name__ == '__main__':
    name = 'aboeladahim'
    password = '@roufa123456789ayman'

    print("Status:", PasswordAuth.register(name, password))
    if PasswordAuth.authenticate(name, '@roufa123456789ayman'):
        print('Login Successful')
    else:
        print('Login Failed')

    if PasswordAuth.authenticate(name, '@roufa123456789yman'):
        print('Login Successful')
    else:
        print('Login Failed')