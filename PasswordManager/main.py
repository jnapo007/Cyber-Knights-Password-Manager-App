from flask import Flask, render_template, request
import hashlib
import urllib.parse
import requests

app = Flask(__name__)


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
        return render_template('updatePassword.html', success=True)


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


# Example usage
create_update_password()

if __name__ == '__main__':
    app.run(debug=True)
