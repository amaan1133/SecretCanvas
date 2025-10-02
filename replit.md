# CipherCanvas - Cryptography + Steganography

## Overview
CipherCanvas is a Python application that combines cryptography and steganography to enable secret communication. Users can encrypt messages with AES and RSA, hide them in images using LSB steganography, and later extract and decrypt them.

## Current State
**Status**: Fully functional
**Last Updated**: October 2, 2025

## Features
- **Tkinter GUI** with two main tabs:
  - Hide Secret Message: Encrypt and embed messages in images
  - Reveal Secret Message: Extract and decrypt hidden messages
- **AES Encryption** using Fernet from cryptography library
- **RSA Key Exchange** (optional) for secure AES key distribution
- **LSB Steganography** to embed encrypted data in PNG images
- **SHA-256 Integrity Verification** to ensure message authenticity
- **Real-time Status Logging** showing encryption/embedding/extraction steps
- **Self-Destruct Feature** to clear extracted message after first read
- **Key Management** with display and save functionality

## Security Implementation
- When RSA is enabled, only the encrypted AES key is displayed (plaintext AES key is hidden for security)
- When RSA is disabled, the plaintext AES key is displayed for direct decryption
- SHA-256 hash verification ensures message integrity before decryption
- RSA-2048 for key encryption with OAEP padding

## Project Architecture
```
.
├── main.py                 # Main application with GUI and all functionality
├── sample_input.png        # Sample image for testing steganography
├── output.png             # Generated image with hidden message (created on hide)
└── replit.md              # Project documentation
```

## How to Use

### Hiding a Message
1. Click "Hide Secret Message" tab
2. Enter your secret message in the text box
3. Browse and select an input PNG image (or use sample_input.png)
4. Check "Use RSA encryption" for enhanced security (recommended)
5. Click "Hide Message in Image"
6. The app will display encryption keys - save them securely!
7. Output image with hidden message is saved as "output.png"

### Revealing a Message
1. Click "Reveal Secret Message" tab
2. Browse and select the image with hidden message (output.png)
3. Enter the encrypted AES key (if RSA was used) or plaintext AES key
4. If RSA was used, check "Use RSA decryption" and paste the RSA private key
5. Optionally enable "Self-destruct after first read" to clear message after 3 seconds
6. Click "Reveal Secret Message"
7. The decrypted message will be displayed

## Dependencies
- Python 3.11
- cryptography (AES Fernet, RSA, SHA-256)
- Pillow (PIL for image manipulation)
- tkinter (GUI, built-in)

## Running the Application
```bash
python main.py
```

## Technical Details

### Encryption Flow
1. Generate AES key using Fernet
2. Compute SHA-256 hash of message
3. Prepend hash to message
4. Encrypt combined data with AES
5. If RSA enabled: encrypt AES key with RSA public key
6. Embed encrypted message in image using LSB steganography

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
