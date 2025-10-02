# CipherCanvas - Cryptography + Steganography

## Overview
CipherCanvas is a Flask web application that combines cryptography and steganography to enable secret communication. Users can encrypt messages with AES and RSA, hide them in images using LSB steganography, and later extract and decrypt them through an intuitive web interface.

## How to Use

### Hiding a Message
1. Click "Hide Secret Message" tab
2. Enter your secret message in the text box
3. Upload a PNG image (or use sample_input.png)
4. Check "Use RSA encryption" for enhanced security (recommended)
5. Click " Hide Message in Image"
6. Save the displayed encryption keys securely
7. Download the output image with the hidden message

### Revealing a Message
1. Click "Reveal Secret Message" tab
2. Upload the image with the hidden message
3. Check "Use RSA decryption" if RSA was used
4. Enter the encrypted AES key (if RSA) or plaintext AES key
5. If using RSA, paste the RSA private key
6. Click " Reveal Secret Message"
7. The decrypted message will be displayed

## Dependencies
- Python 3.11
- Flask (web framework)
- cryptography (AES Fernet, RSA, SHA-256)
- Pillow (PIL for image manipulation)
- Werkzeug (secure file handling)


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
