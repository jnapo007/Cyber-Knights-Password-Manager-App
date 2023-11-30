import base64
import csv
import hashlib
import os
import urllib.parse
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Set a secret key for session management


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/updatePassword.html', methods=['POST'])
def update_password():
    # Get user input from the form
    username = request.form['username']
    password = request.form['password']

    # Validate password
    validation_result = is_valid_password(password)
    if not validation_result['valid']:
        return render_template('index.html', message=validation_result['reason'])

    # Generate SHA-1 hash of the password
    hashed_password = generate_sha1_hash(password)

    # Check if the password is compromised
    compromised = check_password_compromised(hashed_password)

    if compromised:
        return render_template('updatePassword.html', success=False)
    else:
        encrypted_password = encrypt_password(password)
        save_to_csv(username, encrypted_password)
        return render_template('updatePassword.html', success=True)


def save_to_csv(username, encrypted_password):
    # Check if the CSV file exists, if not, create it and write headers
    file_exists = os.path.isfile('passwords.csv')
    with open('passwords.csv', 'a', newline='') as csvfile:
        headers = ['Username', 'Encrypted_Password']
        writer = csv.DictWriter(csvfile, fieldnames=headers)

        if not file_exists:
            writer.writeheader()

        # Write username and encrypted password to the CSV file
        writer.writerow({'Username': username, 'Encrypted_Password': encrypted_password})


def create_update_password():
    messages = []  # List to store messages indicating password issues

    # Get user input for username
    username = input("Enter your username: ")

    # Get user input for password
    while True:
        password = input("Enter your new or existing password: ")

        # Validate password
        if is_valid_password(password):
            break
        else:
            messages.append("Invalid password. Please ensure it meets the criteria.")

    # Check if there are any messages indicating issues with the password
    if messages:
        # Display all the reasons for an invalid password
        for message in messages:
            print(message)
        return  # Return without further processing if password is invalid

    # Generate SHA-1 hash of the password
    hashed_password = generate_sha1_hash(password)

    # Check if the password is compromised
    compromised = check_password_compromised(hashed_password)

    if compromised:
        print("Password compromised! Please choose a different password.")

    else:
        print("Password updated successfully!")
        encrypt_password(password)
    # Here, you might want to store the username and hashed_password securely,
    # such as in a database or another secure storage mechanism.


def is_valid_password(password):
    # Check if the password meets certain criteria
    # For example, you can enforce a minimum length and complexity requirements

    min_length = 8
    if len(password) < min_length:
        return {'valid': False, 'reason': f"Password must be at least {min_length} characters long."}

    # You can add more complexity requirements as needed
    # For example, at least one uppercase letter, one lowercase letter, and one digit
    if not any(c.isupper() for c in password):
        return {'valid': False, 'reason': "Password must contain at least one uppercase letter."}
    if not any(c.islower() for c in password):
        return {'valid': False, 'reason': "Password must contain at least one lowercase letter."}
    if not any(c.isdigit() for c in password):
        return {'valid': False, 'reason': "Password must contain at least one digit."}

    # If the password meets all criteria
    return {'valid': True}


def check_password_compromised(hashed_password):
    # Extract prefix
    prefix = hashed_password[:5]

    # URL-encode the prefix
    encoded_prefix = urllib.parse.quote(prefix)

    # Send request to Pwned Passwords API
    api_url = f'https://api.pwnedpasswords.com/range/{encoded_prefix}'
    response = requests.get(api_url)

    if response.status_code == 200:
        # Print hashed password for debugging
        # print(f'Hashed Password: {hashed_password}')

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
    with open('passwords.csv', 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row['Username'] == username:
                return row['Encrypted_Password']
    return None  # Return None if username is not found in the CSV file


@app.route('/get_password/<username>', methods=['GET'])
# Function to decrypt the encrypted password retrieved from the CSV file
def decrypt_password_for_user(username):
    encrypted_password = get_encrypted_password(username)
    if encrypted_password:
        decrypted_password = decrypt_password(encrypted_password)
        return decrypted_password
    return None  # Return None if username is not found or password is not decrypted


# Example usage
create_update_password()


@app.route('/dashboard')
def show_dashboard():
    if 'logged_in' in session and session['logged_in']:
        # Read credentials from the CSV file
        passwords = []
        with open('passwords.csv', 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                passwords.append(row)

        # Render the dashboard template with the credentials
        return render_template('dashboard.html', credentials=credentials)
    else:
        return redirect(url_for('login'))


# Route to handle adding new credentials
@app.route('/add', methods=['POST'])
def add_credentials():
    website = request.form['website']
    username = request.form['username']
    password = request.form['password']

    with open('credentials.csv', 'a', newline='') as csvfile:
        fieldnames = ['website', 'username', 'password']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writerow({'website': website, 'username': username, 'password': password})

    return redirect(url_for('dashboard'))


# Route for logging in
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Perform authentication (this is a placeholder, replace with your authentication logic)
        # For example, you might check credentials against a database or stored data
        if username == 'your_username' and password == 'your_password':
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            return render_template('dashboard.html', message='Invalid credentials')

    return render_template('dashboard.html')


# Route for logging out
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)