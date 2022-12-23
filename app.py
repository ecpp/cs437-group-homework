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


# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
