# import os
# import uuid
# import qrcode
# import base64
# from PIL import Image
# import atexit
# import sqlite3
# from io import BytesIO
# from datetime import date
# from flask_cors import CORS
# from flask import Flask, request, jsonify
# from apscheduler.schedulers.background import BackgroundScheduler
# import jwt
# import datetime
# from functools import wraps

# # Initialize Flask app
# app = Flask(__name__)
# CORS(app, resources={r"*": {"origins": "*"}})

# # Secret key for JWT encoding/decoding
# SECRET_KEY = 'your_secret_key'  # Change this to a more secure key

# # Database paths
# LOCAL_DB_PATH = "/Users/firdovsirzaev/Desktop/DigiMeal/src/BackScript/DigiMealDemoBack/LoginDemo.db"
# ADMIN_DB_PATH = "/Users/firdovsirzaev/Desktop/DigiMeal/src/BackScript/DigiMealDemoBack/admins_identify.db"  # Proper path
# SCANNER_DB_PATH = "/Users/firdovsirzaev/Desktop/DigiMeal/src/BackScript/DigiMealDemoBack/ScannerLogin.db" #scanner db path

# # Initialize databases
# def init_db():
#     conn = sqlite3.connect(LOCAL_DB_PATH)
#     cursor = conn.cursor()

#     cursor.execute('''CREATE TABLE IF NOT EXISTS identify ( 
#         username TEXT PRIMARY KEY, 
#         password TEXT NOT NULL 
#     )''')

#     cursor.execute('''CREATE TABLE IF NOT EXISTS qr_codes ( 
#         id TEXT PRIMARY KEY, 
#         username TEXT, 
#         image BLOB, 
#         date TEXT, 
#         status INTEGER DEFAULT 1, 
#         status_scanner INTEGER DEFAULT 1, 
#         FOREIGN KEY (username) REFERENCES identify(username) 
#     )''')

#     cursor.execute('''CREATE TABLE IF NOT EXISTS user_page ( 
#         username TEXT PRIMARY KEY, 
#         istifadeci_adi TEXT NOT NULL 
#     )''')

#     conn.commit()
#     conn.close()

#     # Initialize Admin Database
#     conn = sqlite3.connect(ADMIN_DB_PATH)
#     cursor = conn.cursor()
#     cursor.execute('''CREATE TABLE IF NOT EXISTS adminsidenfication (
#         usernameadmin TEXT PRIMARY KEY, 
#         passwordadmin TEXT NOT NULL 
#     )''')
#     cursor.execute('''CREATE TABLE IF NOT EXISTS admin_page (
#         username TEXT PRIMARY KEY, 
#         istifadeci_adi TEXT NOT NULL 
#     )''')
#     conn.commit()
#     conn.close()
#     # scanner
#     conn = sqlite3.connect(SCANNER_DB_PATH)
#     cursor = conn.cursor()
#     cursor.execute('''CREATE TABLE IF NOT EXISTS scanneridenfication (
#         scanner_username TEXT PRIMARY KEY, 
#         scanner_password TEXT NOT NULL 
#     )''')
#     cursor.execute('''CREATE TABLE IF NOT EXISTS scannerpage (
#         scannerusername TEXT PRIMARY KEY, 
#         scanner_istifadeci_adi TEXT NOT NULL, 
#         faculty TEXT NOT NULL
#     )''')
#     conn.commit()
#     conn.close()

# init_db()







# # JWT token generation
# def generate_jwt(username, is_admin=False):
#     expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
#     payload = {
#         'username': username,
#         'is_admin': is_admin,
#         'exp': expiration_time
#     }
#     return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# def check_scanner_login(scanner_username, scanner_password):
#     try:
#         conn = sqlite3.connect(SCANNER_DB_PATH)
#         cursor = conn.cursor()
#         cursor.execute("SELECT * FROM scanneridenfication WHERE scanner_username = ? AND scanner_password = ?", 
#                        (scanner_username, scanner_password))
#         scanner = cursor.fetchone()
#         if scanner:
#             token = generate_jwt(scanner_username, is_admin=False)
#             return {"success": True, "username": scanner_username, "message": "Login successful", "token": token}
#         else:
#             return {"success": False, "message": "Incorrect username or password"}
#     finally:
#         conn.close()

# # Function to check user login
# def check_login(username, password):
#     try:
#         conn = sqlite3.connect(LOCAL_DB_PATH)
#         cursor = conn.cursor()
#         cursor.execute("SELECT * FROM identify WHERE username = ? AND password = ?", (username, password))
#         user = cursor.fetchone()
#         if user:
#             token = generate_jwt(username)
#             return {"success": True, "username": username, "message": "Login successful", "token": token}
#         else:
#             return {"success": False, "message": "Incorrect username or password"}
#     except sqlite3.Error as e:
#         return {"success": False, "message": f"Database error: {str(e)}"}
#     finally:
#         conn.close()


# # Function to check admin login
# def check_admin_login(username, password):
#     try:
#         conn = sqlite3.connect(ADMIN_DB_PATH)
#         cursor = conn.cursor()
#         cursor.execute("SELECT * FROM adminsidenfication WHERE usernameadmin = ? AND passwordadmin = ?", (username, password))
#         admin = cursor.fetchone()
#         if admin:
#             token = generate_jwt(username, is_admin=True)
#             return {"success": True, "username": username, "message": "Login successful", "token": token}
#         else:
#             return {"success": False, "message": "Incorrect username or password"}
#     finally:
#         conn.close()


# # Decorator for token-required routes
# def token_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         token = request.headers.get('Authorization')

#         if not token:
#             return jsonify({'message': 'Token is missing!'}), 403
#         try:
#             token = token.split(" ")[1]  # Extract token part from "Bearer <token>"
#             payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
#             current_user = payload['username']
#             is_admin = payload['is_admin']
#         except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
#             return jsonify({'message': 'Token is invalid!'}), 403

#         # Add user info to the request context
#         request.current_user = current_user
#         request.is_admin = is_admin
#         return f(*args, **kwargs)

#     return decorated_function


# # Routes for user and admin login
# @app.route('/user/login', methods=['POST'])
# def login():
#     data = request.json
#     username = data.get('username')
#     password = data.get('password')

#     if not username or not password:
#         return jsonify({"success": False, "message": "Username and password required"}), 400

#     result = check_login(username, password)
#     return jsonify(result), 200 if result['success'] else 401


# @app.route('/admin/login', methods=['POST'])
# def admin_login():
#     data = request.json
#     username = data.get('username')
#     password = data.get('password')
#     if not username or not password:
#         return jsonify({"success": False, "message": "Username and password required"}), 400
#     result = check_admin_login(username, password)
#     return jsonify(result), 200 if result['success'] else 401

# @app.route('/admin/get_admin_username', methods=['POST'])
# @token_required
# def get_admin_username():
#     # Ensure the request is from an admin user
#     if not request.is_admin:
#         return jsonify({"success": False, "message": "Admin access required"}), 403

#     data = request.json
#     usernameadmin = data.get('usernameadmin')

#     if not usernameadmin:  # Ensuring 'usernameadmin' is provided
#         return jsonify({"success": False, "message": "Username is required"}), 400

#     conn = sqlite3.connect(ADMIN_DB_PATH)
#     cursor = conn.cursor()

#     try:
#         # Query to fetch the admin data
#         cursor.execute('SELECT istifadeci_adi, faculty FROM admin_page WHERE usernameadmin = ?', (usernameadmin,))
#         result = cursor.fetchall()  # Fetch all matching rows

#         # Format the results for response
#         results_for_admin = [{"istifadeciadi": row[0], "faculty": row[1]} for row in result]

#         if results_for_admin:  # Check if results exist
#             return jsonify({"success": True, "results": results_for_admin}), 200
#         else:
#             return jsonify({"success": False, "message": "Username not found"}), 404
#     except sqlite3.Error as e:
#         # Handle database errors
#         return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
#     finally:
#         # Close the database connection
#         conn.close()
# # Route to generate QR code for user
# @app.route('/user/generate_qr', methods=['POST'])
# @token_required
# def generate_qr():
#     data = request.json
#     username = data.get('username')

#     if not username:
#         return jsonify({"success": False, "message": "Username is required."}), 400

#     today = str(date.today())
#     conn = sqlite3.connect(LOCAL_DB_PATH)
#     cursor = conn.cursor()
#     cursor.execute('SELECT id, image, date FROM qr_codes WHERE username = ? AND date = ? AND status = 1',
#                    (username, today))
#     existing_qr = cursor.fetchone()

#     if existing_qr:

#         return jsonify({
#             "success": True,
#             "image": existing_qr[1],
#             "date": existing_qr[2]
#         })

#     # Generate a new QR code if none exists
#     qr_id = str(uuid.uuid4())
#     qr_image = generate_qr_code(username)
#     cursor.execute('''INSERT INTO qr_codes (id, username, image, date, status) VALUES (?, ?, ?, ?, 1)''',
#                    (qr_id, username, qr_image, today))
#     conn.commit()
#     conn.close()

#     return jsonify({
#         "success": True,
#         "image": qr_image,
#         "date": today
#     })


# # Function to generate QR code image
# def generate_qr_code(data):
#     qr = qrcode.QRCode(
#         version=1,
#         error_correction=qrcode.constants.ERROR_CORRECT_L,
#         box_size=10,
#         border=4,
#     )
#     qr.add_data(data)
#     qr.make(fit=True)
#     img = qr.make_image(fill="black", back_color="white")
#     buffered = BytesIO()
#     img.save(buffered, format="PNG")
#     return base64.b64encode(buffered.getvalue()).decode("utf-8")


# # Route to get the username for a user
# @app.route('/user/username', methods=['POST'])
# @token_required
# def get_username():
#     username = request.current_user  # Access username from the request context

#     conn = sqlite3.connect(LOCAL_DB_PATH)
#     cursor = conn.cursor()

#     try:
#         cursor.execute('SELECT istifadeci_adi FROM user_page WHERE username = ?', (username,))
#         result = cursor.fetchone()

#         if result:
#             istifadeci_adi = result[0]
#             return jsonify({"success": True, "istifadeci_adi": istifadeci_adi}), 200
#         else:
#             return jsonify({"success": False, "message": "Username not found"}), 404
#     except sqlite3.Error as e:
#         return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
#     finally:
#         conn.close()
#         # Route to get user QR code history
# @app.route('/user/history/<username>', methods=['GET'])
# @token_required
# def history(username):
#     conn = sqlite3.connect(LOCAL_DB_PATH)
#     cursor = conn.cursor()
#     cursor.execute('SELECT id, date, status_scanner FROM qr_codes WHERE username = ?', (username,))
#     rows = cursor.fetchall()
#     conn.close()

#     qr_data = [{"id": row[0], "date": row[1], "status_scanner": row[2]} for row in rows]
#     return jsonify(qr_data), 200


# # Route to get all QR codes for a user
# @app.route('/user/get_qrs/<username>', methods=['GET'])
# @token_required
# def get_qrs(username):
#     conn = sqlite3.connect(LOCAL_DB_PATH)
#     cursor = conn.cursor()
#     cursor.execute('SELECT id, image, date, status FROM qr_codes WHERE username = ?', (username,))
#     rows = cursor.fetchall()
#     conn.close()

#     qr_data = [{"id": row[0], "image": row[1], "date": row[2], "status": row[3]} for row in rows]
#     return jsonify(qr_data), 200




# #scanner


# @app.route('/scanner/login', methods=['POST'])
# def scanner_login():
#     data = request.json
#     scanner_username = data.get('username')
#     scanner_password = data.get('password')
#     if not scanner_username or not scanner_password:
#         return jsonify({"success": False, "message": "Username and password required"}), 400
#     result = check_scanner_login(scanner_username, scanner_password)
#     return jsonify(result), 200 if result['success'] else 401


# # Route to get scanner username and faculty
# @app.route('/scanner/get_scanner_username', methods=['POST'])
# def get_scanner_username():
#     data = request.json
#     usernamesc = data.get('usernamesc')

#     if not usernamesc:
#         return jsonify({"success": False, "message": "Username is required"}), 400

#     conn = sqlite3.connect(SCANNER_DB_PATH)
#     cursor = conn.cursor()

#     try:
#         cursor.execute('SELECT scanner_istifadeci_adi, faculty FROM scannerpage WHERE scannerusername = ?', 
#                        (usernamesc,))
#         result = cursor.fetchall()

#         results_for_sc = [{"istifadeciadi": row[0], "faculty": row[1]} for row in result]

#         if results_for_sc:
#             return jsonify({"success": True, "results": results_for_sc}), 200
#         else:
#             return jsonify({"success": False, "message": "Username not found"}), 404
#     except sqlite3.Error as e:
#         return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
#     finally:
#         conn.close()
# if __name__ == '__main__':
#     app.run(debug=True)







import os
import uuid
import qrcode
import base64
from PIL import Image
import atexit
import sqlite3
from io import BytesIO
from datetime import date
from flask_cors import CORS
from flask import Flask, request, jsonify
from apscheduler.schedulers.background import BackgroundScheduler
import jwt
import datetime
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"*": {"origins": "*"}})

# Secret key for JWT encoding/decoding
SECRET_KEY = 'your_secret_key'  # Change this to a more secure key

# Database paths
FACADMINS_DB_PATH = '/Users/firdovsirzaev/Desktop/DigiMeal/src/BackScript/DigiMealDemoBack/Admins.db'
LOCAL_DB_PATH = "/Users/firdovsirzaev/Desktop/DigiMeal/src/BackScript/DigiMealDemoBack/LoginDemo.db"
ADMIN_DB_PATH = "/Users/firdovsirzaev/Desktop/DigiMeal/src/BackScript/DigiMealDemoBack/admins_identify.db"  # Proper path
SCANNER_DB_PATH = "/Users/firdovsirzaev/Desktop/DigiMeal/src/BackScript/DigiMealDemoBack/ScannerLogin.db" #scanner db path
# Initialize databases
def init_db():
    conn = sqlite3.connect(LOCAL_DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS identify ( 
        username TEXT PRIMARY KEY, 
        password TEXT NOT NULL 
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS qr_codes ( 
        id TEXT PRIMARY KEY, 
        username TEXT, 
        image BLOB, 
        date TEXT, 
        status INTEGER DEFAULT 1, 
        status_scanner INTEGER DEFAULT 1, 
        FOREIGN KEY (username) REFERENCES identify(username) 
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS user_page ( 
        username TEXT PRIMARY KEY, 
        istifadeci_adi TEXT NOT NULL 
    )''')

    conn.commit()
    conn.close()

    # Initialize Admin Database
    conn = sqlite3.connect(ADMIN_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS adminsidenfication (
        usernameadmin TEXT PRIMARY KEY, 
        passwordadmin TEXT NOT NULL 
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS admin_page (
        username TEXT PRIMARY KEY, 
        istifadeci_adi TEXT NOT NULL 
    )''')
    conn.commit()
    conn.close()
    # scanner
    conn = sqlite3.connect(SCANNER_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS scanneridenfication (
        scanner_username TEXT PRIMARY KEY, 
        scanner_password TEXT NOT NULL 
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS scannerpage (
        scannerusername TEXT PRIMARY KEY, 
        scanner_istifadeci_adi TEXT NOT NULL, 
        faculty TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()
init_db()







# JWT token generation
def generate_jwt(username, is_admin=False):
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {
        'username': username,
        'is_admin': is_admin,
        'exp': expiration_time
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def check_scanner_login(scanner_username, scanner_password):
    try:
        conn = sqlite3.connect(SCANNER_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scanneridenfication WHERE scanner_username = ? AND scanner_password = ?", 
                       (scanner_username, scanner_password))
        scanner = cursor.fetchone()
        if scanner:
            token = generate_jwt(scanner_username, is_admin=False)
            return {"success": True, "username": scanner_username, "message": "Login successful", "token": token}
        else:
            return {"success": False, "message": "Incorrect username or password"}
    finally:
        conn.close()

# Function to check user login
def check_login(username, password):
    try:
        conn = sqlite3.connect(LOCAL_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM identify WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        if user:
            token = generate_jwt(username)
            return {"success": True, "username": username, "message": "Login successful", "token": token}
        else:
            return {"success": False, "message": "Incorrect username or password"}
    except sqlite3.Error as e:
        return {"success": False, "message": f"Database error: {str(e)}"}
    finally:
        conn.close()


# Function to check admin login
def check_admin_login(username, password):
    try:
        conn = sqlite3.connect(ADMIN_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM adminsidenfication WHERE usernameadmin = ? AND passwordadmin = ?", (username, password))
        admin = cursor.fetchone()
        if admin:
            token = generate_jwt(username, is_admin=True)
            return {"success": True, "username": username, "message": "Login successful", "token": token}
        else:
            return {"success": False, "message": "Incorrect username or password"}
    finally:
        conn.close()


# Decorator for token-required routes
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            token = token.split(" ")[1]  # Extract token part from "Bearer <token>"
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user = payload['username']
            is_admin = payload['is_admin']
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({'message': 'Token is invalid!'}), 403

        # Add user info to the request context
        request.current_user = current_user
        request.is_admin = is_admin
        return f(*args, **kwargs)

    return decorated_function


# Routes for user and admin login
@app.route('/user/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required"}), 400

    result = check_login(username, password)
    return jsonify(result), 200 if result['success'] else 401


@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required"}), 400
    result = check_admin_login(username, password)
    return jsonify(result), 200 if result['success'] else 401

@app.route('/admin/get_admin_username', methods=['POST'])
@token_required
def get_admin_username():
    # Ensure the request is from an admin user
    if not request.is_admin:
        return jsonify({"success": False, "message": "Admin access required"}), 403

    data = request.json
    usernameadmin = data.get('usernameadmin')

    if not usernameadmin:  # Ensuring 'usernameadmin' is provided
        return jsonify({"success": False, "message": "Username is required"}), 400

    conn = sqlite3.connect(ADMIN_DB_PATH)
    cursor = conn.cursor()

    try:
        # Query to fetch the admin data
        cursor.execute('SELECT istifadeci_adi, faculty FROM admin_page WHERE usernameadmin = ?', (usernameadmin,))
        result = cursor.fetchall()  # Fetch all matching rows

        # Format the results for response
        results_for_admin = [{"istifadeciadi": row[0], "faculty": row[1]} for row in result]

        if results_for_admin:  # Check if results exist
            return jsonify({"success": True, "results": results_for_admin}), 200
        else:
            return jsonify({"success": False, "message": "Username not found"}), 404
    except sqlite3.Error as e:
        # Handle database errors
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    finally:
        # Close the database connection
        conn.close()
# Route to generate QR code for user
@app.route('/user/generate_qr', methods=['POST'])
@token_required
def generate_qr():
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({"success": False, "message": "Username is required."}), 400

    today = str(date.today())
    conn = sqlite3.connect(LOCAL_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, image, date FROM qr_codes WHERE username = ? AND date = ? AND status = 1',
                   (username, today))
    existing_qr = cursor.fetchone()

    if existing_qr:

        return jsonify({
            "success": True,
            "image": existing_qr[1],
            "date": existing_qr[2]
        })

    # Generate a new QR code if none exists
    qr_id = str(uuid.uuid4())
    qr_image = generate_qr_code(username)
    cursor.execute('''INSERT INTO qr_codes (id, username, image, date, status) VALUES (?, ?, ?, ?, 1)''',
                   (qr_id, username, qr_image, today))
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "image": qr_image,
        "date": today
    })


# Function to generate QR code image
def generate_qr_code(data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode("utf-8")


# Route to get the username for a user
@app.route('/user/username', methods=['POST'])
@token_required
def get_username():
    username = request.current_user  # Access username from the request context

    conn = sqlite3.connect(LOCAL_DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT istifadeci_adi FROM user_page WHERE username = ?', (username,))
        result = cursor.fetchone()

        if result:
            istifadeci_adi = result[0]
            return jsonify({"success": True, "istifadeci_adi": istifadeci_adi}), 200
        else:
            return jsonify({"success": False, "message": "Username not found"}), 404
    except sqlite3.Error as e:
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()
        # Route to get user QR code history
@app.route('/user/history/<username>', methods=['GET'])
@token_required
def history(username):
    conn = sqlite3.connect(LOCAL_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, date, status_scanner FROM qr_codes WHERE username = ?', (username,))
    rows = cursor.fetchall()
    conn.close()

    qr_data = [{"id": row[0], "date": row[1], "status_scanner": row[2]} for row in rows]
    return jsonify(qr_data), 200


# Route to get all QR codes for a user
@app.route('/user/get_qrs/<username>', methods=['GET'])
@token_required
def get_qrs(username):
    conn = sqlite3.connect(LOCAL_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, image, date, status FROM qr_codes WHERE username = ?', (username,))
    rows = cursor.fetchall()
    conn.close()

    qr_data = [{"id": row[0], "image": row[1], "date": row[2], "status": row[3]} for row in rows]
    return jsonify(qr_data), 200




#scanner


@app.route('/scanner/login', methods=['POST'])
def scanner_login():
    data = request.json
    scanner_username = data.get('username')
    scanner_password = data.get('password')
    if not scanner_username or not scanner_password:
        return jsonify({"success": False, "message": "Username and password required"}), 400
    result = check_scanner_login(scanner_username, scanner_password)
    return jsonify(result), 200 if result['success'] else 401


# Route to get scanner username and faculty
@app.route('/scanner/get_scanner_username', methods=['POST'])
def get_scanner_username():
    data = request.json
    usernamesc = data.get('usernamesc')

    if not usernamesc:
        return jsonify({"success": False, "message": "Username is required"}), 400

    conn = sqlite3.connect(SCANNER_DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT scanner_istifadeci_adi, faculty FROM scannerpage WHERE scannerusername = ?', 
                       (usernamesc,))
        result = cursor.fetchall()

        results_for_sc = [{"istifadeciadi": row[0], "faculty": row[1]} for row in result]

        if results_for_sc:
            return jsonify({"success": True, "results": results_for_sc}), 200
        else:
            return jsonify({"success": False, "message": "Username not found"}), 404
    except sqlite3.Error as e:
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()
if __name__ == '__main__':
    app.run(debug=True)