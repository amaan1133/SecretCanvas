# CipherCanvas - Cryptography + Steganography

## Overview
CipherCanvas is a Flask web application that combines cryptography and steganography to enable secret communication. Users can encrypt messages with AES and RSA, hide them in images using LSB steganography, and later extract and decrypt them through an intuitive web interface.

## Current State
**Status**: Fully functional Flask web app
**Last Updated**: October 2, 2025

## Features
- **Modern Web Interface** with two main tabs:
  - Hide Secret Message: Encrypt and embed messages in images
  - Reveal Secret Message: Extract and decrypt hidden messages
- **AES Encryption** using Fernet from cryptography library
- **RSA Key Exchange** (optional) for secure AES key distribution
- **LSB Steganography** to embed encrypted data in PNG images
- **SHA-256 Integrity Verification** to ensure message authenticity
- **File Upload/Download** for seamless image handling
- **Real-time Feedback** with loading indicators and error messages

## Security Implementation
- When RSA is enabled, only the encrypted AES key is displayed (plaintext AES key is hidden for security)
- When RSA is disabled, the plaintext AES key is displayed for direct decryption
- SHA-256 hash verification ensures message integrity before decryption
- RSA-2048 for key encryption with OAEP padding
- Secure file handling with sanitized filenames
- Session-based secret key management

## Project Architecture
```
.
├── main.py                 # Flask backend with crypto/steganography functions
├── templates/
│   └── index.html         # Web interface with hide/reveal tabs
├── static/
│   └── uploads/           # Temporary storage for uploaded/generated images
├── sample_input.png       # Sample image for testing steganography
└── replit.md             # Project documentation
```

## How to Use

### Hiding a Message
1. Click "Hide Secret Message" tab
2. Enter your secret message in the text box
3. Upload a PNG image (or use sample_input.png)
4. Check "Use RSA encryption" for enhanced security (recommended)
5. Click "🔒 Hide Message in Image"
6. Save the displayed encryption keys securely
7. Download the output image with the hidden message

### Revealing a Message
1. Click "Reveal Secret Message" tab
2. Upload the image with the hidden message
3. Check "Use RSA decryption" if RSA was used
4. Enter the encrypted AES key (if RSA) or plaintext AES key
5. If using RSA, paste the RSA private key
6. Click "🔓 Reveal Secret Message"
7. The decrypted message will be displayed

## Dependencies
- Python 3.11
- Flask (web framework)
- cryptography (AES Fernet, RSA, SHA-256)
- Pillow (PIL for image manipulation)
- Werkzeug (secure file handling)

## Running the Application
```bash
python main.py
```
The app will be available at http://localhost:5000

## Technical Details

### Encryption Flow
1. Generate AES key using Fernet
2. Compute SHA-256 hash of message
3. Prepend hash to message
4. Encrypt combined data with AES
5. If RSA enabled: encrypt AES key with RSA public key
6. Embed encrypted message in image using LSB steganography
7. Return encrypted keys and download link

### Decryption Flow
1. Extract encrypted data from image LSB
2. If RSA enabled: decrypt AES key with RSA private key
3. Decrypt message with AES key
4. Separate hash from message
5. Verify SHA-256 hash matches
6. Display original message

### Steganography Method
- LSB (Least Significant Bit) technique
- Embeds data in the least significant bit of RGB pixel values
- First 4 bytes store message length
- Remaining bytes store encrypted message
- Minimal visual impact on image quality

## Web Architecture
- Flask routes handle hide/reveal operations
- File uploads validated for PNG format only
- JSON responses for AJAX requests
- Responsive UI with modern gradient design
- Error handling for user feedback
