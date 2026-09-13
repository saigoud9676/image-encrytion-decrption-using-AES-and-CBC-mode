import os
import base64
import pandas as pd
from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # For flash messages

# Configure directories for image storage
UPLOAD_FOLDER = 'static/original'
ENCRYPTED_FOLDER = 'static/encrypted'
DECRYPTED_FOLDER = 'static/decrypted'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ENCRYPTED_FOLDER'] = ENCRYPTED_FOLDER
app.config['DECRYPTED_FOLDER'] = DECRYPTED_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit upload size to 16MB

# Path to the Excel file that stores user credentials
USER_DATA_FILE = 'user_data.xlsx'

# Function to check if Excel file exists and create it if not
def create_user_data_file():
    if not os.path.exists(USER_DATA_FILE):
        df = pd.DataFrame(columns=["Username", "Password"])
        df.to_excel(USER_DATA_FILE, index=False)

# Function to save user data to Excel
def save_user_data(username, password):
    df = pd.read_excel(USER_DATA_FILE)
    #df = df.append({"Username": username, "Password": password}, ignore_index=True)
    df = pd.concat([df, pd.DataFrame([{"Username": username, "Password": password}])], ignore_index=True)
    df.to_excel(USER_DATA_FILE, index=False)

# Function to validate user login
def validate_user(username, password):
    df = pd.read_excel(USER_DATA_FILE)
    user = df[df["Username"] == username]
    if not user.empty and user.iloc[0]["Password"] == password:
        return True
    return False

# Encryption method using AES
def encrypt_image(image, secret_key):
    img_byte_arr = BytesIO()
    image.save(img_byte_arr, format='PNG')
    img_byte_arr = img_byte_arr.getvalue()

    secret_key = secret_key.ljust(16, '0').encode('utf-8')[:16]
    cipher = AES.new(secret_key, AES.MODE_CBC)
    padded_data = pad(img_byte_arr, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)

    iv = base64.b64encode(cipher.iv).decode('utf-8')
    encrypted_image_path = os.path.join(app.config['ENCRYPTED_FOLDER'], 'encrypted_image.png')
    with open(encrypted_image_path, 'wb') as f:
        f.write(encrypted_data)

    return encrypted_image_path, iv

# Decryption method using AES
def decrypt_image(encrypted_image_path, secret_key, iv):
    with open(encrypted_image_path, 'rb') as f:
        encrypted_data = f.read()

    iv = base64.b64decode(iv)
    secret_key = secret_key.ljust(16, '0').encode('utf-8')[:16]
    cipher = AES.new(secret_key, AES.MODE_CBC, iv=iv)

    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    img = Image.open(BytesIO(decrypted_data))

    decrypted_image_path = os.path.join(app.config['DECRYPTED_FOLDER'], 'decrypted_image.png')
    img.save(decrypted_image_path)

    return decrypted_image_path

@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template('home.html')  # Default homepage route

@app.route('/upload-and-encrypt', methods=['GET', 'POST'])
def upload_and_encrypt():
    if request.method == 'POST':
        file = request.files.get('image')  # Use .get to avoid KeyError if 'image' is missing
        secret_key = request.form.get('key')  # Use .get for safety

        if not file or file.filename == '':
            flash("No file selected for upload!", "danger")
            return render_template('index.html')  # Stay on the same page with an error

        if not secret_key:
            flash("Encryption key is required!", "danger")
            return render_template('index.html')  # Stay on the same page with an error

        # Save the original image
        original_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(original_path)

        # Encrypt the image
        try:
            image = Image.open(original_path)
            encrypted_image_path, iv = encrypt_image(image, secret_key)
            return render_template(
                'index.html',
                encrypted_image_path=os.path.basename(encrypted_image_path),
                iv=iv,
                uploaded_image_path=file.filename,
            )
        except Exception as e:
            flash(f"An error occurred during encryption: {str(e)}", "danger")
            return render_template('index.html')  # Stay on the same page with an error

    return render_template('index.html')  # For GET requests, show the empty form


@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_image_path = request.form.get('encrypted_image')
    secret_key = request.form.get('key')
    iv = request.form.get('iv')

    if not encrypted_image_path or not secret_key or not iv:
        flash("Missing required decryption fields.", "danger")
        return render_template('index.html')  # Stay on the same page with an error

    encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], os.path.basename(encrypted_image_path))

    try:
        decrypted_image_path = decrypt_image(encrypted_path, secret_key, iv)
        return render_template(
            'index.html',
            decrypted_image_path=os.path.basename(decrypted_image_path),
            encrypted_image_path=encrypted_image_path,
            iv=iv,
        )
    except Exception as e:
        flash(f"Decryption failed: {str(e)}", "danger")
        return render_template('index.html')  # Stay on the same page with an error

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    filename = filename.replace("\\", "/")
    folder_mapping = {
        'original': app.config['UPLOAD_FOLDER'],
        'encrypted': app.config['ENCRYPTED_FOLDER'],
        'decrypted': app.config['DECRYPTED_FOLDER']
    }

    folder = None
    for prefix, folder_path in folder_mapping.items():
        if filename.startswith(prefix):
            folder = folder_path
            break

    if not folder:
        folder = 'static'

    return send_from_directory(folder, filename)

@app.route('/register', methods=['GET', 'POST'])
def register():
    create_user_data_file()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password == confirm_password:
            save_user_data(username, password)
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))  # Redirect to login after successful registration
        else:
            flash('Passwords do not match!', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if user credentials are valid
        if validate_user(username, password):
            return redirect(url_for('upload_and_encrypt'))  # Redirect to upload page (index) after successful login
        else:
            flash("Invalid credentials", "danger")
            return render_template('login.html')  # Stay on login page if invalid credentials

    return render_template('login.html')  # This will render your login page if GET request

@app.route('/overview')
def about():
    encrypted_image_path = request.args.get('encrypted_image_path')  # Get the encrypted image path from the URL
    iv = request.args.get('iv')  # Get the iv from the URL

    return render_template('overview.html', encrypted_image_path=encrypted_image_path, iv=iv)

if __name__ == '__main__':
    app.run(debug=True)
