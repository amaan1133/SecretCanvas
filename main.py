from flask import Flask, render_template, request, jsonify, send_file, session
import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from PIL import Image
import io
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', os.urandom(24))
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 16 * 1024 * 1024

ALLOWED_EXTENSIONS = {'png'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(message, use_rsa=True):
    aes_key = Fernet.generate_key()
    fernet = Fernet(aes_key)

    message_hash = hashlib.sha256(message.encode()).digest()
    message_with_hash = message_hash + message.encode()

    encrypted_message = fernet.encrypt(message_with_hash)

    result = {
        'encrypted_message': encrypted_message,
        'aes_key': aes_key
    }

    if use_rsa:
        private_key, public_key = generate_rsa_keys()

        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        result['encrypted_aes_key'] = encrypted_aes_key
        result['private_key'] = private_pem
        result['public_key'] = public_pem

    return result

def decrypt_message(encrypted_message, aes_key):
    fernet = Fernet(aes_key)

    decrypted_data = fernet.decrypt(encrypted_message)

    message_hash = decrypted_data[:32]
    message = decrypted_data[32:]

    computed_hash = hashlib.sha256(message).digest()

    if message_hash != computed_hash:
        raise ValueError("Message integrity check failed!")

    return message.decode()

def hide_in_image(image_path, encrypted_message):
    img = Image.open(image_path)

    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = list(img.getdata())

    message_bytes = encrypted_message
    message_length = len(message_bytes)

    length_bytes = message_length.to_bytes(4, byteorder='big')
    data_to_hide = length_bytes + message_bytes

    binary_data = ''.join(format(byte, '08b') for byte in data_to_hide)

    max_capacity = len(pixels) * 3
    if len(binary_data) > max_capacity:
        raise ValueError(f"Image too small! Need {len(binary_data)} bits, have {max_capacity}")

    new_pixels = []
    data_index = 0

    for pixel in pixels:
        r, g, b = pixel

        if data_index < len(binary_data):
            r = (r & 0xFE) | int(binary_data[data_index])
            data_index += 1

        if data_index < len(binary_data):
            g = (g & 0xFE) | int(binary_data[data_index])
            data_index += 1

        if data_index < len(binary_data):
            b = (b & 0xFE) | int(binary_data[data_index])
            data_index += 1

        new_pixels.append((r, g, b))

    new_img = Image.new('RGB', img.size)
    new_img.putdata(new_pixels)

    output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'output.png')
    new_img.save(output_path, 'PNG')

    return output_path

def extract_from_image(image_path):
    img = Image.open(image_path)

    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = list(img.getdata())

    binary_data = ''
    for pixel in pixels:
        r, g, b = pixel
        binary_data += str(r & 1)
        binary_data += str(g & 1)
        binary_data += str(b & 1)

        if len(binary_data) >= 32:
            break

    length = int(binary_data[:32], 2)

    bits_needed = 32 + (length * 8)

    binary_data = ''
    for pixel in pixels:
        r, g, b = pixel
        binary_data += str(r & 1)
        binary_data += str(g & 1)
        binary_data += str(b & 1)

        if len(binary_data) >= bits_needed:
            break

    message_bits = binary_data[32:bits_needed]

    message_bytes = bytearray()
    for i in range(0, len(message_bits), 8):
        byte = message_bits[i:i+8]
        message_bytes.append(int(byte, 2))

    return bytes(message_bytes)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/hide', methods=['POST'])
def hide():
    try:
        message = request.form.get('message')
        use_rsa = request.form.get('use_rsa') == 'true'

        if not message:
            return jsonify({'error': 'No message provided'}), 400

        if 'image' not in request.files:
            return jsonify({'error': 'No image file'}), 400

        file = request.files['image']

        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': 'Only PNG files are allowed'}), 400

        filename = secure_filename(file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(input_path)

        encryption_result = encrypt_message(message, use_rsa)

        output_path = hide_in_image(input_path, encryption_result['encrypted_message'])

        response_data = {
            'success': True,
            'output_image': '/download/output.png',
            'use_rsa': use_rsa
        }

        if use_rsa:
            response_data['encrypted_aes_key'] = base64.b64encode(encryption_result['encrypted_aes_key']).decode()
            response_data['private_key'] = encryption_result['private_key'].decode()
            response_data['public_key'] = encryption_result['public_key'].decode()
        else:
            response_data['aes_key'] = base64.b64encode(encryption_result['aes_key']).decode()

        return jsonify(response_data)

    except Exception as e:
        import traceback
        error_msg = str(e)
        print(f"Error in /hide: {error_msg}")
        print(traceback.format_exc())
        return jsonify({'error': error_msg}), 500

@app.route('/reveal', methods=['POST'])
def reveal():
    try:
        use_rsa = request.form.get('use_rsa') == 'true'
        aes_key_input = request.form.get('aes_key')

        if not aes_key_input:
            return jsonify({'error': 'No AES key provided'}), 400

        if 'image' not in request.files:
            return jsonify({'error': 'No image file'}), 400

        file = request.files['image']

        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': 'Only PNG files are allowed'}), 400

        filename = secure_filename(file.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(image_path)

        if use_rsa:
            private_key_pem = request.form.get('private_key')

            if not private_key_pem:
                return jsonify({'error': 'No RSA private key provided'}), 400

            try:
                # Clean up the PEM key - ensure proper formatting
                private_key_pem = private_key_pem.strip()
                private_key = serialization.load_pem_private_key(
                    private_key_pem.encode(),
                    password=None
                )
            except Exception as pem_error:
                return jsonify({'error': f'Invalid RSA private key format: {str(pem_error)}. Make sure to copy the entire key including -----BEGIN PRIVATE KEY----- and -----END PRIVATE KEY----- lines.'}), 400

            encrypted_aes_key = base64.b64decode(aes_key_input)
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        else:
            aes_key = base64.b64decode(aes_key_input)

        encrypted_message = extract_from_image(image_path)

        decrypted_message = decrypt_message(encrypted_message, aes_key)

        return jsonify({
            'success': True,
            'message': decrypted_message
        })

    except Exception as e:
        import traceback
        error_msg = str(e)
        print(f"Error in /reveal: {error_msg}")
        print(traceback.format_exc())
        return jsonify({'error': error_msg}), 500

@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)
