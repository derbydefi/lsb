# ⧉ LSB Steganography Tool


## Overview

The **LSB Steganography Tool** is a web-based application that allows users to hide and retrieve secret messages or files within images using the Least Significant Bit (LSB) technique. This tool ensures that the embedded data remains invisible to the naked eye while preserving the original image quality.

## Features

- **Encode Messages and Files**: Embed text messages or upload files to hide within an image.
- **Decode Data**: Extract hidden messages or files from encoded images.
- **Optional Encryption**: Protect your hidden data with a password using advanced encryption algorithms:
  - Passwords are hashed with **PBKDF2** (100,000 iterations, SHA-256).
  - Data is encrypted using **AES-GCM (256-bit)**, ensuring confidentiality and integrity.
- **Visual Comparison**: View original, encoded, and difference images to assess changes.
- **Customizable Settings**:
  - Select specific color channels (Red, Green, Blue) for encoding.
  - Adjust bit depth per channel to balance between data capacity and image quality.
  - Option to fill remaining image space with random data for added security.
- **Offline Usage**: This tool is fully self-contained and works offline. Simply download the `index.html` file and open it in any modern web browser to use.

## Link

Access the live tool [here](https://steg.tools).

## Usage

### Encoding Data

1. **Upload Source Image**:
   - Click on the "Source Image" input in the write section to select the image you want to embed data into.

2. **Enter Message or Upload File**:
   - **Message**: Type your secret message into the "Enter Message" text area.
   - **File**: Click on the "Upload File" input to select a file you wish to hide within the image.

3. **Set Optional Password**:
   - If you want to encrypt your data, enter a strong password in the "Enter Password (Optional)" field.

4. **Configure Encoding Settings**:
   - **Encoding Color Channels**: Select which color channels (Red, Green, Blue) to use for embedding.
   - **Bit Depth Per Channel**: Adjust the number of bits per selected channel.
   - **Fill Remaining Space**: Check this option to fill unused bits with random data, enhancing security.

5. **Encode Data**:
   - Click the "Encode Data" button. Once processing is complete, download the encoded image using the provided link.

6. **View Encoded Images**:
   - Toggle the "Show Images" button to view the original, encoded, and difference images.

### Decoding Data

1. **Upload Encoded Image**:
   - Click on the "Upload Image" input under the decoding section to upload the image containing hidden data.

2. **Enter Password (If Encrypted)**:
   - If the data was encrypted during encoding, enter the corresponding password in the "Password (if required)" field.

3. **Decode Data**:
   - Click the "Decode Data" button. Upon successful decoding, the hidden message and/or file will be displayed with options to download them.

## Offline Usage

This tool is self-contained and requires no server or internet connection. To use the tool offline:

1. Download the `index.html` file from the repository.
2. Open the file in any modern web browser (e.g., Chrome, Firefox, Edge).
3. The tool will function as it does online, allowing you to encode and decode data seamlessly.

## License
This project is licensed under the MIT License
