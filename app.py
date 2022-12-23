import flask
from mysql.connector import connect
import hashlib
import jwt

# Set the database connection parameters
db_host = '91.191.173.36'
db_user = 'erencopcu'
db_password = 'eren1505'
db_name = 'securitylab'

# Create a Flask app
app = flask.Flask(__name__)

SECRET_KEY = 'group-homework'


# Define the route for the endpoint
@app.route('/register', methods=['POST'])
def register():
    # Get the data from the POST request without json.
    username = flask.request.form['username']
    password = flask.request.form['password']
    password = hashlib.sha256(password.encode()).hexdigest()

    # Connect to the database
    connection = connect(host=db_host, user=db_user, password=db_password, database=db_name)
    cursor = connection.cursor()

    # check if user exists
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    if user:
        return "User already exists", 400

    # Insert the username and password into the users table
    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
    connection.commit()

    # Close the cursor and connection
    cursor.close()
    connection.close()

    # Return a success response
    return "Success", 201


@app.route('/login', methods=['POST'])
def login():
    username = flask.request.form['username']
    password = flask.request.form['password']
    password = hashlib.sha256(password.encode()).hexdigest()

    connection = connect(host=db_host, user=db_user, password=db_password, database=db_name)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
    user = cursor.fetchone()
    if user is None or not user.check_password(password):
        return 'Error: Invalid username or password', 401

    cursor.close()
    connection.close()

    return 'User logged in successfully'


@app.route('/register-user')
def show_registration_page():
    return flask.render_template('userregister.html')


# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
