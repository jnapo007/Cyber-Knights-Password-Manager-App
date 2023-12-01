import base64
import csv
import hashlib
import os
import urllib.parse
import requests
from flask import jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Set a secret key for session management


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/update', methods=['POST'])
def update_password():
    # Get user input from the form
    username = request.form['username']
    password = request.form['password']

    # Validate password
    validation_result = is_valid_password(password)
    if not validation_result['valid']:
        return render_template('register.html', message=validation_result['reason'])

    # Generate SHA-1 hash of the password
    hashed_password = generate_sha1_hash(password)

    # Check if the password is compromised
    compromised = check_password_compromised(hashed_password)

    if compromised:
        return render_template('update.html', success=False)
    else:
        encrypted_password = encrypt_password(password)
        save_to_csv(username, encrypted_password)
        return render_template('update.html', success=True)


def save_to_csv(username, encrypted_password):
    # Check if the CSV file exists, if not, create it and write headers
    file_exists = os.path.isfile('static/passwords.csv')
    with open('static/passwords.csv', 'a', newline='') as csvfile:
        headers = ['username', 'encrypted_password']
        writer = csv.DictWriter(csvfile, fieldnames=headers)

        if not file_exists:
            writer.writeheader()

        # Write username and encrypted password to the CSV file
        writer.writerow({'username': username, 'encrypted_password': encrypted_password})


def is_valid_password(password):
    min_length = 16
    if len(password) < min_length:
        return {'valid': False, 'reason': f"password must be at least {min_length} characters long."}

    if not any(c.isupper() for c in password):
        return {'valid': False, 'reason': "password must contain at least one uppercase letter."}

    if not any(c.islower() for c in password):
        return {'valid': False, 'reason': "password must contain at least one lowercase letter."}

    if not any(c.isdigit() for c in password):
        return {'valid': False, 'reason': "password must contain at least one digit."}

    # Check if the password is compromised
    hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    compromised = check_password_compromised(hashed_password)
    if compromised:
        return {'valid': False, 'reason': "password is compromised and should not be used."}

    return {'valid': True}


def check_password_compromised(hashed_password):
    # Extract prefix
    prefix = hashed_password[:5]

    # URL-encode the prefix
    encoded_prefix = urllib.parse.quote(prefix)

    # Send request to Pwned passwords API
    api_url = f'https://api.pwnedpasswords.com/range/{encoded_prefix}'
    response = requests.get(api_url)

    if response.status_code == 200:
        # Print hashed password for debugging
        # print(f'Hashed password: {hashed_password}')

        # Print the API response for debugging
        # print(response.text)

        # Check if the full hash is present in the response
        suffixes = [line.split(':')[0] for line in response.text.splitlines()]

        compromised = any(suffix.upper() == hashed_password[5:].upper() for suffix in suffixes)
        return compromised
    else:
        # Handle API request error
        print(f"Error: {response.status_code}")
        return False


def generate_sha1_hash(password):
    # Create a new SHA-1 hash object
    sha1_hash = hashlib.sha1()

    # Update the hash object with the UTF-8 encoded password
    sha1_hash.update(password.encode('utf-8'))

    # Get the hexadecimal representation of the hash
    hashed_password = sha1_hash.hexdigest()
    return hashed_password


def encrypt_password(password):
    # Define the encryption key
    key = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
    # Encode the plaintext password as bytes
    plaintext = password.encode()
    # Apply PKCS7 padding to the plaintext
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Initialize the IV (Initialization Vector)
    iv = b'\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20'
    # Create an AES cipher in CBC mode with the specified key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    # Create an encryptor object
    encryptor = cipher.encryptor()
    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Base64 encode the ciphertext and convert to UTF-8
    encrypted_pw = base64.b64encode(ciphertext).decode('utf-8')
    return encrypted_pw


def decrypt_password(encrypted_pw):
    # Define the decryption key
    key = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
    # Initialize the IV (Initialization Vector)
    iv = b'\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20'

    # Base64 decode the encrypted password
    encrypted_bytes = base64.b64decode(encrypted_pw)
    # Create an AES cipher in CBC mode with the specified key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    # Create a decryptor object
    decryptor = cipher.decryptor()
    # Decrypt the ciphertext
    decrypted_bytes = decryptor.update(encrypted_bytes) + decryptor.finalize()

    # Apply PKCS7 unpadding to the decrypted result
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_bytes) + unpadder.finalize()
    # Decode the bytes to get the decrypted password
    decrypted_pw = plaintext.decode('utf-8')

    return decrypted_pw


# Function to retrieve the encrypted password for a given username from the CSV file
def get_encrypted_password(username):
    with open('static/passwords.csv', 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row['username'] == username:
                return row['Encrypted_password']
    return None  # Return None if username is not found in the CSV file


@app.route('/get_password/<username>', methods=['GET'])
# Function to decrypt the encrypted password retrieved from the CSV file
def decrypt_password_for_user(username):
    encrypted_password = get_encrypted_password(username)
    if encrypted_password:
        decrypted_password = decrypt_password(encrypted_password)
        return decrypted_password
    return None  # Return None if username is not found or password is not decrypted


def get_user_credentials(username):
    user_credentials = []
    with open('static/credentials.csv', mode='r', newline='') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row['username'] == username:
                obscured_password = '*' * len(row['password'])
                user_credentials.append(
                    {'website': row['website'], 'username': row['username'], 'password': obscured_password})
    return user_credentials


@app.route('/dashboard')
def show_dashboard():
    if 'logged_in' in session and session['logged_in']:
        username = session['username']  # Retrieve the username from the session
        user_credentials = get_user_credentials(username)
        return render_template('dashboard.html', credentials=user_credentials, username=username)
    else:
        return redirect(url_for('dashboard'))


# Route to handle adding new credentials
@app.route('/add', methods=['POST'])
def add_credentials():
    website = request.form['website']
    username = request.form['username']
    password = request.form['password']

    with open('static/credentials.csv', 'a', newline='') as csvfile:
        fieldnames = ['website', 'username', 'password']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writerow({'website': website, 'username': username, 'password': password})

    return redirect(url_for('dashboard'))


def write_to_csv(data):
    file_exists = os.path.isfile('static/credentials.csv')

    with open('static/credentials.csv', mode='a', newline='') as file:
        fieldnames = ['website', 'username', 'password']
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        # Write header row if the file is newly created
        if not file_exists:
            writer.writeheader()

        # Write data to the CSV file
        writer.writerow({'website': data['website'], 'username': data['username'], 'password': data['password']})


# Route to handle adding new credentials
@app.route('/saveLogin', methods=['POST'])
def save_login():
    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']

        # Validate the password
        validation_result = is_valid_password(password)
        if not validation_result['valid']:
            # Render the template with the error message
            return render_template('dashboard.html', message=validation_result['reason'])

            # Check if the password is compromised
        hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        compromised = check_password_compromised(hashed_password)
        if compromised:
            return {'valid': False, 'reason': "password is compromised and should not be used."}

        # Encrypt the password before saving
        encrypted_password = encrypt_password(password)

        # Create a dictionary with the new login info
        new_login = {'website': website, 'username': username, 'password': encrypted_password}

        # Write the new login info to the credentials CSV file
        write_to_csv(new_login)

        # Redirect back to the dashboard after saving
        return redirect(url_for('show_dashboard'))

valid_username = 'your_valid_username'  # Set your valid username here



# Define a function to get valid usernames from passwords.csv
def get_valid_username():
    usernames = []
    with open('static/passwords.csv', 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            usernames.append(row['username'])
    return usernames


@app.route('/login', methods=['GET', 'POST'])
def login():
    valid_usernames = get_valid_username()  # Get valid usernames from passwords.csv
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Get encrypted password for the provided username from the CSV
        encrypted_password = get_encrypted_password(username)

        if encrypted_password and encrypted_password == encrypt_password(password):
            session['logged_in'] = True
            session['username'] = username  # Store the username in the session
            return redirect(url_for('show_dashboard'))
        else:
            return render_template('index.html', message='Invalid credentials')

    return render_template('dashboard.html')


# Route for logging out
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return render_template('index.html', message='You have been logged out.')


if __name__ == '__main__':
    app.run(debug=True)
