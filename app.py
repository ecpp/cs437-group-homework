import flask
import requests
from mysql.connector import connect
import hashlib
import jwt
import datetime
import random
import json

DB_HOST = '91.191.173.36'
DB_USER = 'erencopcu'
DB_PASS = 'eren1505'
DB_NAME = 'securitylab'
VIRUSTOTAL_API_KEY = 'af966f850472ecf26721001e6896ea600de1049fa2bed03a6f63eb1aff0da156'
VIRUSTOTAL_API_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'

app = flask.Flask(__name__)
SECRET_KEY = 'group-homework'


# API request to VirusTotal to retrieve information about an IP address.
def get_virustotal_info(ip_address):
    try:
        url = VIRUSTOTAL_API_URL + ip_address
        headers = {"x-apikey": VIRUSTOTAL_API_KEY,
                   "accept": "application/json"}  # my API KEY

        response = requests.get(url, headers=headers)
        info = ""
        data = response.json()
        info += "Harmless: " + str(data["data"]["attributes"]["last_analysis_stats"]["harmless"]) + " "
        info += "Malicious: " + str(data["data"]["attributes"]["last_analysis_stats"]["malicious"]) + " "
        info += "Suspicious: " + str(data["data"]["attributes"]["last_analysis_stats"]["suspicious"]) + " "
        info += "Undetected: " + str(data["data"]["attributes"]["last_analysis_stats"]["undetected"]) + " "
        info += "Reputation: " + str(data["data"]["attributes"]["reputation"])
    except:
        info = "API RATE EXCEEDED"
    return info


# Checks if the login or password attempt is malicious or not.
# If there are more than 5 attempts in last 30 seconds from same IP address, it is malicious.
def is_attempt_malicious(attempt_timestamp):
    db_connection = connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME
    )
    cursor = db_connection.cursor()
    end_timestamp = attempt_timestamp
    start_timestamp = end_timestamp - datetime.timedelta(seconds=30)

    query = '''
        SELECT COUNT(*)
        FROM login_attempts
        WHERE timestamp >= %s AND timestamp <= %s
    '''
    cursor.execute(query, (start_timestamp, end_timestamp))
    attempts = cursor.fetchone()[0]

    cursor.close()

    if attempts >= 5:
        return 'malicious'
    else:
        return 'normal'


# Get the ISP and country of the IP address
# Sends a request to whois server and parses the response
# Returns the ISP and country
def get_isp_and_country(ip_address):
    whois_server = 'ipleak.net'
    response = requests.get(f'https://{whois_server}/{ip_address}')
    isp = response.text.split('ISP: ')[1].split(' ')[0]
    isp = isp.replace('</td><td>', '')
    country = response.text.split('Country: ')[1].split(' ')[3]
    country = country.split('"')[1]
    return isp, country


# Logs the login attempt to the MySQL database
def log_attempt(ip_address, country, whois, status, attempt, verdict, virustotal):
    # Connect to the database
    connection = connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME
    )

    cursor = connection.cursor()

    sql = "INSERT INTO login_attempts (ip_address, country, whois, status, attempt, verdict, VirusTotalInfo) VALUES (%s, %s, %s, %s, %s, %s, %s)"
    values = (ip_address, country, whois, status, attempt, verdict, virustotal)
    cursor.execute(sql, values)

    connection.commit()

    cursor.close()
    connection.close()


# Registers the user to the database
# If the user already exists, it returns an error
# If the user does not exist, it creates the user and returns to the login page
@app.route('/register', methods=['POST'])
def register():
    username = flask.request.form['username']
    password = flask.request.form['password']
    password = hashlib.sha256(password.encode()).hexdigest()

    connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    if user:
        return "User already exists", 400

    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
    connection.commit()

    cursor.close()
    connection.close()

    return flask.redirect('/login-user')


# Logs the user in
# If the user does not exist, it returns an error
# If the user exists, it checks the password
# If the password is wrong, it returns an error
# If the password is correct, it generates a JWT token and returns it to the user
# It also logs the login attempt to the database
@app.route('/login', methods=['POST'])
def login():
    username = flask.request.form['username']
    password = flask.request.form['password']
    password = hashlib.sha256(password.encode()).hexdigest()

    connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
    user = cursor.fetchone()
    isp, country = get_isp_and_country(flask.request.remote_addr)

    if user is None:
        log_attempt(flask.request.remote_addr, country, isp, 'fail',
                    'login',
                    is_attempt_malicious(datetime.datetime.now()),
                    get_virustotal_info(flask.request.remote_addr))
        return 'Error: Invalid username or password', 401
    cursor.close()
    connection.close()
    # Generate JWT token
    token = jwt.encode({'user_id': user[0]}, SECRET_KEY, algorithm='HS256')

    log_attempt(flask.request.remote_addr, country, isp, 'success',
                'login',
                is_attempt_malicious(datetime.datetime.now()),
                get_virustotal_info(flask.request.remote_addr))
    resp = flask.make_response(token)
    resp.set_cookie('token', token)
    return resp, 200


@app.route('/api/password_recovery_info')
def api_password_recovery_info():
    return flask.render_template('passwordrecoveryinfo.html')


@app.route('/api/login_info')
def api_login_info():
    return flask.render_template('logininfoapi.html')


# Authentication REST API endpoint is below.
@app.route('/api/login', methods=['POST'])
def api_login():
    # Parse the JSON data from the request
    data = flask.request.get_json()

    # Extract two fields from the data
    username = str(data['username'])
    password = str(data['password'])
    password = hashlib.sha256(password.encode()).hexdigest()

    connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
    user = cursor.fetchone()
    isp, country = get_isp_and_country(flask.request.remote_addr)

    if user is None:
        log_attempt(flask.request.remote_addr, country, isp, 'fail',
                    'login',
                    is_attempt_malicious(datetime.datetime.now()),
                    get_virustotal_info(flask.request.remote_addr))
        return flask.jsonify({'result': "Incorrect username and/or password!"})
    cursor.close()
    connection.close()

    log_attempt(flask.request.remote_addr, country, isp, 'success',
                'login',
                is_attempt_malicious(datetime.datetime.now()), get_virustotal_info(flask.request.remote_addr))
    return flask.jsonify({'result': "Success! You're in."})


# Password recovery REST API endpoint is below.
@app.route('/api/password_recovery', methods=['POST'])
def api_password_recovery():
    # Parse the JSON data from the request
    data = flask.request.get_json()

    # Extract the three fields from the data
    username = str(data['username'])
    code = int(data['reset-code'])
    password = str(data['new-password'])

    # Database connection
    connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
    cursor = connection.cursor()

    cursor.execute(f"SELECT * FROM users WHERE username = '{username}' and resetcode = {int(code)}")
    correct = cursor.fetchone()
    isp, country = get_isp_and_country(flask.request.remote_addr)

    if correct:
        password = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute(f"UPDATE `users` SET `password` = '{password}' WHERE `users`.`username` = '{username}'")
        connection.commit()
        cursor.close()
        connection.close()
        log_attempt(flask.request.remote_addr, country, isp, 'success',
                    'password_recovery',
                    is_attempt_malicious(datetime.datetime.now()),
                    get_virustotal_info(flask.request.remote_addr))
        # Return the result as a JSON response
        return flask.jsonify({'result': "Success! Changed password."})
    else:
        cursor.close()
        connection.close()
        log_attempt(flask.request.remote_addr, country, isp, 'fail',
                    'password_recovery',
                    is_attempt_malicious(datetime.datetime.now()),
                    get_virustotal_info(flask.request.remote_addr))
        # Return the result as a JSON response
        return flask.jsonify({'result': "Incorrect username and/or reset-code!"})


# Logs out the user
# Deletes the session cookie
@app.route('/logout', methods=['DELETE'])
def logout():
    response = flask.make_response()
    response.delete_cookie('token')

    return response, 200


# Testing for the JWT token
@app.route('/protected', methods=['GET'])
def protected():
    token = flask.request.cookies.get('token')
    if token is None:
        return 'Error: No token provided', 401

    try:
        jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.exceptions.InvalidSignatureError:
        return 'Error: Invalid JWT', 401
    return 'Success', 200


usernameWhoForgotPassword = ""


@app.route('/register-user')
def show_registration_page():
    return flask.render_template('register.html')


@app.route('/forget-password-user')
def show_general_forget_page():
    return flask.render_template('generalforget.html')


@app.route('/forget-password-user-not-found')
def show_username_not_found_forget_password():
    return flask.render_template('usernamenotfound.html')


# When a user makes a POST request to this endpoint, the server retrieves the new password
# from the request form data and hashes it using the SHA256 algorithm.
# It then updates the password field in the users table of the database
# with the hashed password, using the global variable usernameWhoForgotPassword
# to identify the user whose password is being reset. Finally, the server redirects the user back to the login page.
@app.route('/created_new_password', methods=['POST'])
def change_password():
    password = flask.request.form['password']
    password = hashlib.sha256(password.encode()).hexdigest()

    connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
    cursor = connection.cursor()
    global usernameWhoForgotPassword
    if usernameWhoForgotPassword != "":
        cursor.execute(
            f"UPDATE `users` SET `password` = '{password}' WHERE `users`.`username` = '{usernameWhoForgotPassword}'")
        connection.commit()
    usernameWhoForgotPassword = ""
    cursor.close()
    connection.close()

    return flask.redirect('/login-user')


@app.route('/reset_password')
def reset_password():
    global usernameWhoForgotPassword
    if usernameWhoForgotPassword == "":
        return flask.redirect('/login-user')
    return flask.render_template('passwordreset.html', username=usernameWhoForgotPassword)


@app.route('/forget_password_enter_reset_code/<usernameArgument>')
def enter_reset_code(usernameArgument):
    return flask.render_template('resetcode.html', username=usernameArgument)


# When a user makes a POST request to this endpoint with their username as a route parameter,
# the server retrieves the code from the request form data and checks if it matches the reset code stored
# in the database for that user. If the code is correct, the server sets a global variable usernameWhoForgotPassword to
# the provided username and redirects the user to the page where they can enter a new password. If the code is incorrect,
# the server redirects the user back to the page where they can enter the reset code again.
@app.route('/reset_code_check/<username>', methods=['POST'])
def reset_code_check(username):
    code = flask.request.form['code']
    isp, country = get_isp_and_country(flask.request.remote_addr)
    connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
    cursor = connection.cursor()

    cursor.execute(f"SELECT * FROM users WHERE username = '{username}' and resetcode = {int(code)}")
    correct = cursor.fetchone()

    cursor.close()
    connection.close()

    if correct:
        # print("Correct code!")
        global usernameWhoForgotPassword
        usernameWhoForgotPassword = str(username)
        log_attempt(flask.request.remote_addr, country, isp, 'success',
                    'reset_code_check',
                    is_attempt_malicious(datetime.datetime.now()),
                    get_virustotal_info(flask.request.remote_addr))
        return flask.redirect('/reset_password')
    else:
        log_attempt(flask.request.remote_addr, country, isp, 'fail',
                    'reset_code_check',
                    is_attempt_malicious(datetime.datetime.now()),
                    get_virustotal_info(flask.request.remote_addr))
        return flask.redirect(flask.url_for('enter_reset_code', usernameArgument=username))


# When a user makes a POST request to this endpoint with their username, the server checks if a user
# with the provided username exists in the database. If the user exists, the server generates a random four-digit number
# as the reset code and updates the resetcode field in the users table of the database with this code.
# The server then redirects the user to the page where they can enter the reset code to initiate the password
# reset process. If the provided username is not found in the database, the server redirects the user to a page
# indicating that the username was not found.
@app.route('/general_forget_username', methods=['POST'])
def check_username_in_forget_password():
    username = flask.request.form['username']
    userExists = False
    connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
    cursor = connection.cursor()
    isp, country = get_isp_and_country(flask.request.remote_addr)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    if user:
        userExists = True
    if (userExists):
        # UPDATE `users` SET `resetcode` = '1907' WHERE `users`.`id` = 4;
        number = random.randint(1000, 9999)
        print(f'Random number: {number}')
        cursor.execute(f"UPDATE `users` SET `resetcode` = '{number}' WHERE `users`.`username` = '{str(username)}'")
        connection.commit()
        cursor.close()
        connection.close()
        log_attempt(flask.request.remote_addr, country, isp, 'success',
                    'create_reset_code',
                    is_attempt_malicious(datetime.datetime.now()),
                    get_virustotal_info(flask.request.remote_addr))
        return flask.redirect(flask.url_for('enter_reset_code', usernameArgument=username))
        # return flask.redirect('/forget-password-enter-reset-code', usernameArgument=str(username))
    else:
        log_attempt(flask.request.remote_addr, country, isp, 'fail',
                    'create_reset_code',
                    is_attempt_malicious(datetime.datetime.now()),
                    get_virustotal_info(flask.request.remote_addr))
        return flask.redirect('/forget-password-user-not-found')


# This endpoint serves the login page to the user. Before serving the page, the server checks if
# the user has a valid JWT (JSON Web Token) stored in their cookies. If the user has a valid JWT,
# this means that they are already authenticated and the server returns a message indicating that
# they are already logged in. If the user does not have a valid JWT, the server serves the login page to the user.
@app.route('/login-user')
def show_login_page():
    token = flask.request.cookies.get('token')
    if token is not None:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except jwt.exceptions.InvalidSignatureError:
            return 'Error: Invalid JWT', 401
        return 'Already logged in', 200
    return flask.render_template('login.html')


@app.route('/is-logged-in')
def is_logged_in():
    return flask.render_template('protected.html')


# This endpoint serves the admin page to the user. Before serving the page, the server checks
# if the user has a valid JWT stored in their cookies. If the user does not have a valid JWT,
# the server returns an error message indicating that the user is not logged in.
# If the user has a valid JWT, the server decodes the JWT to retrieve the user's ID and uses it to fetch the user's
# information from the database. If the user has the role "admin", the server retrieves login attempt logs
# from the database and renders the admin page with the logs. If the user does not have the role "admin",
# the server returns an error message indicating that the user is not an admin.
@app.route('/admin')
def admin():
    token = flask.request.cookies.get('token')
    if token is None:
        return 'Error: Not logged in', 401
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.exceptions.InvalidSignatureError:
        return 'Error: Invalid JWT', 401
    connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (payload['user_id'],))
    user = cursor.fetchone()
    if user[4] == 'admin':
        cursor.execute("SELECT * FROM login_attempts ORDER BY timestamp DESC")
        logs = cursor.fetchall()

        return flask.render_template('admin.html', logs=logs)
    return 'Not admin', 401


# This endpoint serves the index page to the user. Before rendering the page, the server checks
# if the user has a valid JWT stored in their cookies. If the user has a valid JWT, the server decodes
# the JWT to retrieve the user's ID and uses it to fetch the user's information from the database.
# The server then renders the index page with the login status, username, and admin status of the user.
# If the user does not have a valid JWT, the server renders the index page with the login status set to false.
@app.route('/')
def index():
    token = flask.request.cookies.get('token')
    login_status = False
    username = None
    is_admin = False
    if token is not None:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except jwt.exceptions.InvalidSignatureError:
            return 'Error: Invalid JWT', 401
        login_status = True
        connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id = %s", (payload['user_id'],))
        user = cursor.fetchone()
        username = user[1]
        if user[4] == 'admin':
            is_admin = True
    return flask.render_template('index.html', logged_in=login_status, username=username, admin=is_admin)


if __name__ == '__main__':
    app.config['DEBUG'] = True
    app.run(host='0.0.0.0', port=5000, debug=True)
