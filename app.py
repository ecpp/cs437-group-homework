import flask
import requests
from mysql.connector import connect
import hashlib
import jwt
import datetime

db_host = '91.191.173.36'
db_user = 'erencopcu'
db_password = 'eren1505'
db_name = 'securitylab'

app = flask.Flask(__name__)
SECRET_KEY = 'group-homework'


def is_login_attempt_malicious(login_attempt_timestamp):
    db_connection = connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database=db_name
    )
    cursor = db_connection.cursor()
    end_timestamp = login_attempt_timestamp
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


def get_isp_and_country(ip_address):
    whois_server = 'ipleak.net'
    ip_address = '176.33.69.178'
    response = requests.get(f'https://{whois_server}/{ip_address}')
    isp = response.text.split('ISP: ')[1].split(' ')[0]
    isp = isp.replace('</td><td>', '')
    country = response.text.split('Country: ')[1].split(' ')[3]
    country = country.split('"')[1]
    return isp, country


def log_login_attempt(ip_address, country, whois, status, verdict):
    # Connect to the database
    connection = connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database=db_name
    )

    cursor = connection.cursor()

    sql = "INSERT INTO login_attempts (ip_address, country, whois, status, attempt, verdict) VALUES (%s, %s, %s, %s, %s, %s)"
    values = (ip_address, country, whois, status, 'login', verdict)
    cursor.execute(sql, values)

    connection.commit()

    cursor.close()
    connection.close()


@app.route('/register', methods=['POST'])
def register():
    username = flask.request.form['username']
    password = flask.request.form['password']
    password = hashlib.sha256(password.encode()).hexdigest()

    connection = connect(host=db_host, user=db_user, password=db_password, database=db_name)
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


@app.route('/login', methods=['POST'])
def login():
    username = flask.request.form['username']
    password = flask.request.form['password']
    password = hashlib.sha256(password.encode()).hexdigest()

    connection = connect(host=db_host, user=db_user, password=db_password, database=db_name)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
    user = cursor.fetchone()
    isp, country = get_isp_and_country(flask.request.remote_addr)
    if user is None:
        log_login_attempt(flask.request.remote_addr, country, isp, 'fail',
                          is_login_attempt_malicious(datetime.datetime.now()))
        return 'Error: Invalid username or password', 401
    cursor.close()
    connection.close()

    token = jwt.encode({'user_id': user[0]}, SECRET_KEY, algorithm='HS256')

    log_login_attempt(flask.request.remote_addr, country, isp, 'success',
                      is_login_attempt_malicious(datetime.datetime.now()))
    resp = flask.make_response(token)
    resp.set_cookie('token', token)
    return resp, 200


@app.route('/logout', methods=['DELETE'])
def logout():
    response = flask.make_response()
    response.delete_cookie('token')

    return response, 200


@app.route('/protected', methods=['GET'])
def protected():
    token = flask.request.cookies.get('token')
    if token is None:
        return 'Error: No token provided', 401

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.exceptions.InvalidSignatureError:
        return 'Error: Invalid JWT', 401
    return 'Success', 200


@app.route('/register-user')
def show_registration_page():
    return flask.render_template('register.html')


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


@app.route('/admin')
def admin():
    token = flask.request.cookies.get('token')
    if token is None:
        return 'Error: Not logged in', 401
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.exceptions.InvalidSignatureError:
        return 'Error: Invalid JWT', 401
    connection = connect(host=db_host, user=db_user, password=db_password, database=db_name)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (payload['user_id'],))
    user = cursor.fetchone()
    if user[4] == 'admin':
        cursor.execute("SELECT * FROM login_attempts ORDER BY timestamp DESC")
        logs = cursor.fetchall()

        return flask.render_template('admin.html', logs=logs)
    return 'Not admin', 401


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
        connection = connect(host=db_host, user=db_user, password=db_password, database=db_name)
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
