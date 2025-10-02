CipherCanvas - Cryptography + Steganography
Overview
CipherCanvas is a Flask web application that combines cryptography and steganography to enable secret communication. Users can encrypt messages with AES and RSA, hide them in images using LSB steganography, and later extract and decrypt them through an intuitive web interface.

How to Use
Hiding a Message
Click "Hide Secret Message" tab
Enter your secret message in the text box
Upload a PNG image (or use sample_input.png)
Check "Use RSA encryption" for enhanced security (recommended)
Click " Hide Message in Image"
Save the displayed encryption keys securely
Download the output image with the hidden message
Revealing a Message
Click "Reveal Secret Message" tab
Upload the image with the hidden message
Check "Use RSA decryption" if RSA was used
Enter the encrypted AES key (if RSA) or plaintext AES key
If using RSA, paste the RSA private key
Click " Reveal Secret Message"
The decrypted message will be displayed
Dependencies
Python 3.11
Flask (web framework)
cryptography (AES Fernet, RSA, SHA-256)
Pillow (PIL for image manipulation)
Werkzeug (secure file handling)
Encryption Flow
Generate AES key using Fernet
Compute SHA-256 hash of message
Prepend hash to message
Encrypt combined data with AES
If RSA enabled: encrypt AES key with RSA public key
Embed encrypted message in image using LSB steganography
Return encrypted keys and download link
Decryption Flow
Extract encrypted data from image LSB
If RSA enabled: decrypt AES key with RSA private key
Decrypt message with AES key
Separate hash from message
Verify SHA-256 hash matches
Display original message
Steganography Method
LSB (Least Significant Bit) technique
Embeds data in the least significant bit of RGB pixel values
First 4 bytes store message length
Remaining bytes store encrypted message
Minimal visual impact on image quality
Web Architecture
Flask routes handle hide/reveal operations
File uploads validated for PNG format only
JSON responses for AJAX requests
Responsive UI with modern gradient design
Error handling for user feedback
