/*
 * LSB Steganography Tool
 * Copyright (c) 2024 derbydefi
 * Released under the MIT License
 * See the full license text at the bottom of index.html
 */
const canvas = document.getElementById("canvas");
const ctx = canvas.getContext("2d");
let maxDataSize = 0;
let amplificationFactor = 16; // Default value
let uploadedFileData = null;
let originalImageData = null;
let encodedImageData = null;
const originalCanvas = document.getElementById("originalCanvas");
const originalCtx = originalCanvas.getContext("2d");
const encodedCanvas = document.getElementById("encodedCanvas");
const encodedCtx = encodedCanvas.getContext("2d");
const differenceCanvas = document.getElementById("differenceCanvas");
const differenceCtx = differenceCanvas.getContext("2d");

// UI Elements
const toggleImagesButton = document.getElementById("toggleImagesButton");
const imagesSection = document.getElementById("imagesSection");
const spinner = document.getElementById("spinner");
const messageBox = document.getElementById("messageBox");
const decodeButton = document.getElementById("decodeButton");
const encodeButton = document.getElementById("encodeButton");
const downloadDecodedFile = document.getElementById("downloadDecodedFile");
const downloadLink = document.getElementById("downloadLink");
const amplificationSlider = document.getElementById("amplificationSlider");
const amplificationValue = document.getElementById("amplificationValue");
const fillRandomDataCheckbox = document.getElementById("fillRandomData");
const channelRed = document.getElementById("channelRed");
const channelGreen = document.getElementById("channelGreen");
const channelBlue = document.getElementById("channelBlue");
const bitDepthInput = document.getElementById("bitDepth");
const messageInput = document.getElementById("messageInput");
const uploadFileInput = document.getElementById("uploadFile");
const uploadImageWriteInput = document.getElementById("uploadImageWrite");
const uploadImageReadInput = document.getElementById("uploadImageRead");
const decodedMessage = document.getElementById("decodedMessage");
const messageSizeSpan = document.getElementById("messageSize");
const fileSizeSpan = document.getElementById("fileSize");
const totalDataSizeSpan = document.getElementById("totalDataSize");
const maxBytesSpan = document.querySelector("#maxBytes span");
const capacityFill = document.getElementById("capacityFill");
const totalDataSizeLine = document.getElementById("totalDataSizeLine");

toggleImagesButton.textContent = "Show Images";
const DEFAULT_PASSWORD = "password";

function generateRandomBytes(size) {
	const MAX_BYTES = 65536; // Maximum bytes per call
	const bytes = new Uint8Array(size);
	let generated = 0;

	while (generated < size) {
		const chunkSize = Math.min(MAX_BYTES, size - generated);
		const chunk = new Uint8Array(chunkSize);
		window.crypto.getRandomValues(chunk);
		bytes.set(chunk, generated);
		generated += chunkSize;
	}

	return bytes;
}

function encodeText(text) {
	return new TextEncoder().encode(text);
}

function decodeText(data) {
	return new TextDecoder().decode(data);
}

async function encodeData(data, message, fileData, password) {
	let totalDataBytes = new Uint8Array();
	let hasText = message.length > 0;
	let hasFile = fileData !== null;

	if (!hasText && !hasFile) {
		showMessage("No data to encode.");
		return;
	}

	// Prepare text data
	if (hasText) {
		const messageEncoded = encodeText(message);
		const textLengthBuffer = new ArrayBuffer(4);
		new DataView(textLengthBuffer).setUint32(0, messageEncoded.length);
		const textBytes = new Uint8Array([
			...new Uint8Array(textLengthBuffer),
			...messageEncoded,
		]);
		totalDataBytes = hasFile ? new Uint8Array([...textBytes]) : textBytes;
	}

	// Prepare file data
	if (hasFile) {
		const fileInput = uploadFileInput;
		const file = fileInput.files[0];
		const fileName = file.name;
		const mimeType = file.type;
		const fileNameBytes = encodeText(fileName);
		const mimeTypeBytes = encodeText(mimeType);

		// Log the lengths
		console.log("File Name Length:", fileNameBytes.length);
		console.log("MIME Type Length:", mimeTypeBytes.length);

		// Prepare the lengths as 4-byte Uint32
		const fileNameLengthBuffer = new ArrayBuffer(4);
		new DataView(fileNameLengthBuffer).setUint32(0, fileNameBytes.length);
		const mimeTypeLengthBuffer = new ArrayBuffer(4);
		new DataView(mimeTypeLengthBuffer).setUint32(0, mimeTypeBytes.length);

		const fileContentBytes = new Uint8Array(fileData);

		// Now construct fileBytes
		const fileBytes = new Uint8Array(
			fileNameLengthBuffer.byteLength +
				fileNameBytes.length +
				mimeTypeLengthBuffer.byteLength +
				mimeTypeBytes.length +
				fileContentBytes.length
		);

		let offset = 0;
		fileBytes.set(new Uint8Array(fileNameLengthBuffer), offset);
		offset += fileNameLengthBuffer.byteLength;
		fileBytes.set(fileNameBytes, offset);
		offset += fileNameBytes.length;
		fileBytes.set(new Uint8Array(mimeTypeLengthBuffer), offset);
		offset += mimeTypeLengthBuffer.byteLength;
		fileBytes.set(mimeTypeBytes, offset);
		offset += mimeTypeBytes.length;
		fileBytes.set(fileContentBytes, offset);

		if (hasText) {
			// Append fileBytes to totalDataBytes
			const combinedLength = totalDataBytes.length + fileBytes.length;
			const combinedBytes = new Uint8Array(combinedLength);
			combinedBytes.set(totalDataBytes, 0);
			combinedBytes.set(fileBytes, totalDataBytes.length);
			totalDataBytes = combinedBytes;
		} else {
			totalDataBytes = fileBytes;
		}
	}

	const pwd = password || DEFAULT_PASSWORD;

	// Always encrypt the combined data
	try {
		totalDataBytes = await encryptData(totalDataBytes, pwd);
	} catch (error) {
		showMessage("Encryption failed. Please try again.", true);
		return;
	}

	// Get selected channels and bit depth
	const selectedChannels = getSelectedChannels();
	const bitDepth = getBitDepth();

	// Prepare header with new settings
	let header = {
		hasText: hasText,
		hasFile: hasFile,
		encrypted: true,
		dataLength: totalDataBytes.length,
		channels: selectedChannels,
		bitDepth: bitDepth,
	};

	let headerString = JSON.stringify(header);
	let headerBytes = encodeText(headerString);
	let headerLength = headerBytes.length;

	// Ensure header length fits in one byte
	if (headerLength > 255) {
		showMessage("Header is too large.", true);
		return;
	}

	// Encode header length and header bytes into LSB of red channel
	let dataIndex = 0;
	for (let bit = 7; bit >= 0; bit--) {
		let bitValue = (headerLength >> bit) & 1;
		data[dataIndex] = (data[dataIndex] & ~1) | bitValue;
		dataIndex += 4; // Move to next pixel
	}

	for (let i = 0; i < headerLength; i++) {
		let byte = headerBytes[i];
		for (let bit = 7; bit >= 0; bit--) {
			let bitValue = (byte >> bit) & 1;
			data[dataIndex] = (data[dataIndex] & ~1) | bitValue;
			dataIndex += 4; // Move to next pixel
		}
	}

	// Now dataIndex points to the next pixel after the header
	// We can proceed to encode the data
	const bitsPerPixel = selectedChannels.length * bitDepth;
	let bitPosIndex = 0;

	// Generate channel-bit positions based on selected channels and bit depth
	let channelBitPositions = [];
	for (let channel of selectedChannels) {
		for (let bit = 0; bit < bitDepth; bit++) {
			channelBitPositions.push({ channel, bit });
		}
	}

	// Encode data using selected settings
	for (let i = 0; i < totalDataBytes.length; i++) {
		let byte = totalDataBytes[i];
		for (let bit = 7; bit >= 0; bit--) {
			let bitValue = (byte >> bit) & 1;

			let pixelOffset = Math.floor(bitPosIndex / bitsPerPixel);
			let bitWithinPixel = bitPosIndex % bitsPerPixel;
			let { channel, bit: channelBit } = channelBitPositions[bitWithinPixel];

			let dataIdx = dataIndex + pixelOffset * 4;
			let channelIndex = { R: 0, G: 1, B: 2 }[channel];
			let baseIndex = dataIdx + channelIndex;

			let bitMask = 1 << channelBit;
			data[baseIndex] = (data[baseIndex] & ~bitMask) | (bitValue << channelBit);

			bitPosIndex++;
		}
	}

	// If the fill random data option is enabled, fill the remaining space with random data
	if (isFillRandomDataEnabled()) {
		const totalAvailableBits = (data.length / 4 - dataIndex / 4) * bitsPerPixel;
		const totalRequiredBits = totalDataBytes.length * 8;
		const remainingBits = totalAvailableBits - totalRequiredBits;
		const remainingBytes = Math.floor(remainingBits / 8);

		if (remainingBytes > 0) {
			const randomBytes = generateRandomBytes(remainingBytes);
			for (let i = 0; i < randomBytes.length; i++) {
				let byte = randomBytes[i];
				for (let bit = 7; bit >= 0; bit--) {
					let bitValue = (byte >> bit) & 1;

					let pixelOffset = Math.floor(bitPosIndex / bitsPerPixel);
					let bitWithinPixel = bitPosIndex % bitsPerPixel;
					let { channel, bit: channelBit } =
						channelBitPositions[bitWithinPixel];

					let dataIdx = dataIndex + pixelOffset * 4;
					let channelIndex = { R: 0, G: 1, B: 2 }[channel];
					let baseIndex = dataIdx + channelIndex;

					let bitMask = 1 << channelBit;
					data[baseIndex] =
						(data[baseIndex] & ~bitMask) | (bitValue << channelBit);

					bitPosIndex++;
				}
			}
		}
	}
}

async function decodeData(data, password) {
	let dataIndex = 0;

	// Read header length from LSB of red channel
	let headerLength = 0;
	for (let bitIndex = 7; bitIndex >= 0; bitIndex--) {
		let bit = data[dataIndex] & 1;
		headerLength |= bit << bitIndex;
		dataIndex += 4;
	}

	// Read header bytes
	let headerBytes = new Uint8Array(headerLength);
	for (let i = 0; i < headerLength; i++) {
		let byte = 0;
		for (let bitIndex = 7; bitIndex >= 0; bitIndex--) {
			let bit = data[dataIndex] & 1;
			byte |= bit << bitIndex;
			dataIndex += 4;
		}
		headerBytes[i] = byte;
	}
	const headerString = decodeText(headerBytes);
	const header = JSON.parse(headerString);

	// Get settings from header
	const selectedChannels = header.channels;
	const bitDepth = header.bitDepth;

	// Generate positions
	let channelBitPositions = [];
	for (let channel of selectedChannels) {
		for (let bit = 0; bit < bitDepth; bit++) {
			channelBitPositions.push({ channel, bit });
		}
	}

	const bitsPerPixel = channelBitPositions.length;
	let bitPosIndex = 0;
	let dataBytes = new Uint8Array(header.dataLength);

	// Decode data using settings
	for (let i = 0; i < header.dataLength; i++) {
		let byte = 0;
		for (let bitIndex = 7; bitIndex >= 0; bitIndex--) {
			let pixelOffset = Math.floor(bitPosIndex / bitsPerPixel);
			let bitWithinPixel = bitPosIndex % bitsPerPixel;
			let { channel, bit: channelBit } = channelBitPositions[bitWithinPixel];

			let dataIdx = dataIndex + pixelOffset * 4;
			let channelIndex = { R: 0, G: 1, B: 2 }[channel];
			let baseIndex = dataIdx + channelIndex;

			let bitMask = 1 << channelBit;
			let bit = (data[baseIndex] & bitMask) >> channelBit;

			byte |= bit << bitIndex;
			bitPosIndex++;
		}
		dataBytes[i] = byte;
	}
	let binaryData;
	const pwd = password || DEFAULT_PASSWORD;
	try {
		binaryData = await decryptData(dataBytes, pwd);
		console.log("binaryData decrypted");
	} catch (e) {
		showMessage(
			"Failed to decrypt data. Please check the password or data integrity."
		);
		return null;
	}

	let result = {};

	let offset = 0;

	// Extract text message if present
	if (header.hasText) {
		const textLengthBytes = binaryData.slice(offset, offset + 4);
		const textLength = new DataView(textLengthBytes.buffer).getUint32(0);
		offset += 4;
		const textBytes = binaryData.slice(offset, offset + textLength);
		offset += textLength;
		const message = decodeText(textBytes);
		result.text = message;
	}

	if (header.hasFile) {
		const fileNameLength = new DataView(binaryData.buffer, offset, 4).getUint32(
			0
		);
		offset += 4;
		const fileName = decodeText(
			binaryData.slice(offset, offset + fileNameLength)
		);
		offset += fileNameLength;

		const mimeTypeLength = new DataView(binaryData.buffer, offset, 4).getUint32(
			0
		);
		offset += 4;
		const mimeType = decodeText(
			binaryData.slice(offset, offset + mimeTypeLength)
		);
		offset += mimeTypeLength;

		const fileContent = binaryData.slice(offset);
		result.file = {
			fileName,
			mimeType,
			content: fileContent,
		};

		// Log the lengths
		console.log("Decoded File Name Length:", fileNameLength);
		console.log("Decoded MIME Type Length:", mimeTypeLength);
	}

	return result;
}

async function generateKey(password, salt) {
	const keyMaterial = await window.crypto.subtle.importKey(
		"raw",
		encodeText(password),
		{ name: "PBKDF2" },
		false,
		["deriveKey"]
	);
	return window.crypto.subtle.deriveKey(
		{
			name: "PBKDF2",
			salt: salt,
			iterations: 100000,
			hash: "SHA-256",
		},
		keyMaterial,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"]
	);
}

async function encryptData(data, password) {
	console.log("encryptData function starting...");
	console.log("data:", data);
	console.log("password", password);

	const salt = window.crypto.getRandomValues(new Uint8Array(16));
	const iv = window.crypto.getRandomValues(new Uint8Array(12));
	const key = await generateKey(password, salt);

	console.log("salt:", salt);
	console.log("iv:", iv);
	console.log("key:", key);
	const encrypted = await window.crypto.subtle.encrypt(
		{ name: "AES-GCM", iv: iv },
		key,
		data
	);
	const ciphertext = new Uint8Array(encrypted);
	console.log("ciphertext:", ciphertext);

	// Concatenate salt + iv + ciphertext
	const combinedData = new Uint8Array(
		salt.length + iv.length + ciphertext.length
	);
	combinedData.set(salt, 0);
	combinedData.set(iv, salt.length);
	combinedData.set(ciphertext, salt.length + iv.length);
	console.log("combined data:", combinedData);
	return combinedData;
}

async function decryptData(encryptedData, password) {
	console.log("starting decryptData function...");
	console.log("encryptedData:", encryptedData);
	console.log("password:", password);

	const salt = encryptedData.slice(0, 16);
	const iv = encryptedData.slice(16, 28);
	const ciphertext = encryptedData.slice(28);
	console.log("salt:", salt);
	console.log("iv:", iv);
	console.log("ciphertext:", ciphertext);

	const key = await generateKey(password, salt);
	console.log("decryptkey", key);
	try {
		const decrypted = await window.crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: iv },
			key,
			ciphertext
		);
		console.log("decryptdebugdecrypt:successssss here");
		return new Uint8Array(decrypted);
	} catch (e) {
		console.error("Decryption failed:", e);
		throw new Error("Incorrect password or corrupted data.");
	}
}

function updateMaxDataSize(img) {
	const selectedChannels = getSelectedChannels();
	const bitDepth = getBitDepth();
	const numChannels = selectedChannels.length;

	const availableBits = img.width * img.height * numChannels * bitDepth;
	maxDataSize = Math.floor(availableBits / 8);

	maxBytesSpan.textContent = maxDataSize;
	updateTotalDataSize();
}

function updateCapacityBar(totalDataSize) {
	const capacityUsed = (totalDataSize / maxDataSize) * 100;

	capacityFill.style.width = `${Math.min(capacityUsed, 100)}%`;

	if (capacityUsed > 100) {
		capacityFill.style.backgroundColor = "#f44336"; // Red when over capacity
	} else {
		capacityFill.style.backgroundColor = "#4caf50"; // Green when within capacity
	}
}

function updateTotalDataSize() {
	const messageSize = parseInt(messageSizeSpan.textContent) || 0;
	const fileSize = parseInt(fileSizeSpan.textContent) || 0;
	let totalDataSize = messageSize + fileSize;

	totalDataSize += 44; // 16 bytes salt + 12 bytes iv + 16 bytes tag

	totalDataSizeSpan.textContent = totalDataSize;

	if (maxDataSize > 0 && totalDataSize > maxDataSize) {
		const overBy = totalDataSize - maxDataSize;
		showMessage(
			`Total data size exceeds the maximum capacity of the image by ${overBy} bytes.`,
			true
		);
		document.getElementById("encodeButton").disabled = true;
		totalDataSizeLine.classList.add("over-limit");
	} else {
		clearMessage();
		updateEncodeButtonState();
		totalDataSizeLine.classList.remove("over-limit");
	}

	updateCapacityBar(totalDataSize);
}

function updateEncodeSettings() {
	const img = uploadImageWriteInput.files[0];
	if (img) {
		// Recalculate max data size
		const reader = new FileReader();
		reader.onload = () => {
			const image = new Image();
			image.onload = () => {
				updateMaxDataSize(image);
			};
			image.src = reader.result;
		};
		reader.readAsDataURL(img);
	}
	updateEncodeButtonState();
}

function renderDifferenceImage(originalImageData, encodedImageData) {
	const width = originalImageData.width;
	const height = originalImageData.height;

	const diffImageData = differenceCtx.createImageData(width, height);
	const diffData = diffImageData.data;

	const originalData = originalImageData.data;
	const encodedData = encodedImageData.data;

	for (let i = 0; i < originalData.length; i += 4) {
		// Compute the absolute difference for each color channel
		const rDiff = Math.abs(originalData[i] - encodedData[i]);
		const gDiff = Math.abs(originalData[i + 1] - encodedData[i + 1]);
		const bDiff = Math.abs(originalData[i + 2] - encodedData[i + 2]);

		// Amplify the difference for visibility
		diffData[i] = Math.min(rDiff * amplificationFactor, 255);
		diffData[i + 1] = Math.min(gDiff * amplificationFactor, 255);
		diffData[i + 2] = Math.min(bDiff * amplificationFactor, 255);
		diffData[i + 3] = 255; // Set alpha channel to fully opaque
	}

	differenceCtx.putImageData(diffImageData, 0, 0);
}

function toggleImagesSection() {
	if (imagesSection.classList.contains("show")) {
		imagesSection.classList.remove("show");
		toggleImagesButton.textContent = "Show Images";
	} else {
		imagesSection.classList.add("show");
		toggleImagesButton.textContent = "Hide Images";
	}
}

function showSpinner() {
	spinner.style.display = "block";
}

function hideSpinner() {
	spinner.style.display = "none";
}

function showMessage(text, isError = true) {
	messageBox.className = isError ? "error" : "success";
	messageBox.textContent = text;
	messageBox.style.display = "block";

	// Start fade-out after 4 seconds (display duration)
	setTimeout(() => {
		messageBox.classList.add("fade-out");
	}, 4000);

	// Hide after 5 seconds (allowing 1 second for fade-out)
	setTimeout(() => {
		messageBox.style.display = "none";
		messageBox.classList.remove("fade-out");
	}, 5000);
}

function clearMessage() {
	messageBox.textContent = "";
	messageBox.style.display = "none";
	messageBox.classList.remove("fade-out");
}

function isFillRandomDataEnabled() {
	return fillRandomDataCheckbox.checked;
}

function getSelectedChannels() {
	const channels = [];
	if (channelRed.checked) channels.push("R");
	if (channelGreen.checked) channels.push("G");
	if (channelBlue.checked) channels.push("B");
	return channels;
}

function getBitDepth() {
	const bitDepth = parseInt(bitDepthInput.value);
	return Math.min(Math.max(bitDepth, 1), 16);
}

function updateEncodeButtonState() {
	const imageUploaded = uploadImageWriteInput.files.length > 0;
	const messageProvided = messageInput.value.length > 0 || uploadedFileData;
	const messageSize = parseInt(messageSizeSpan.textContent) || 0;
	const fileSize = parseInt(fileSizeSpan.textContent) || 0;
	const totalDataSize = messageSize + fileSize;

	const canEncode =
		imageUploaded && messageProvided && totalDataSize <= maxDataSize;
	document.getElementById("encodeButton").disabled = !canEncode;
}

function updateDecodeButtonState() {
	const imageUploaded = uploadImageReadInput.files.length > 0;
	decodeButton.disabled = !imageUploaded;
}

encodeButton.addEventListener("click", async () => {
	clearMessage();
	showSpinner();
	try {
		const fileInput = uploadImageWriteInput;
		const message = messageInput.value;
		const password = document.getElementById("passwordInput").value;

		if (!fileInput.files.length) {
			showMessage("Please upload an image.");
			return;
		}

		if (!message && !uploadedFileData) {
			showMessage("Please enter a message or upload a file to encode.");
			return;
		}

		const file = fileInput.files[0];
		const reader = new FileReader();
		reader.onload = () => {
			const img = new Image();
			img.onload = async () => {
				canvas.width = img.width;
				canvas.height = img.height;
				ctx.drawImage(img, 0, 0);
				const imageData = ctx.getImageData(0, 0, img.width, img.height);
				// Copy the original image data
				originalImageData = new ImageData(
					new Uint8ClampedArray(imageData.data),
					imageData.width,
					imageData.height
				);

				await encodeData(imageData.data, message, uploadedFileData, password);
				ctx.putImageData(imageData, 0, 0);
				encodedImageData = ctx.getImageData(0, 0, img.width, img.height);

				// Render the encoded image on encodedCanvas
				encodedCanvas.width = img.width;
				encodedCanvas.height = img.height;
				encodedCtx.putImageData(encodedImageData, 0, 0);

				// Compute and render the difference image
				renderDifferenceImage(originalImageData, encodedImageData);

				canvas.toBlob((blob) => {
					const url = URL.createObjectURL(blob);
					downloadLink.style.display = "inline";
					downloadLink.href = url;
					downloadLink.download = "encoded-image.png";
					downloadLink.textContent = "Download Encoded Image";
				}, "image/png");

				showMessage("Encoding completed successfully!", false);
				// Automatically show the images section after encoding
				if (!imagesSection.classList.contains("show")) {
					imagesSection.classList.add("show");
					toggleImagesButton.textContent = "Hide Images";
				}
			};
			img.src = reader.result;
		};
		reader.readAsDataURL(file);
	} catch (error) {
		showMessage("An error occurred during encoding.");
	} finally {
		hideSpinner();
	}
});

decodeButton.addEventListener("click", async () => {
	clearMessage();
	showSpinner();
	try {
		const password = document.getElementById("passwordInputDecode").value;

		if (!uploadImageReadInput.files.length) {
			showMessage("Please upload an image.");
			return;
		}
		const file = uploadImageReadInput.files[0];
		const reader = new FileReader();
		reader.onload = () => {
			const img = new Image();
			img.onload = async () => {
				canvas.width = img.width;
				canvas.height = img.height;
				ctx.drawImage(img, 0, 0);
				const imageData = ctx.getImageData(0, 0, img.width, img.height);
				const result = await decodeData(imageData.data, password);

				if (!result) return;

				if (result.text) {
					decodedMessage.style.display = "block";
					decodedMessage.querySelector("span").textContent = result.text;
				} else {
					decodedMessage.style.display = "none";
				}

				if (result.file) {
					const blob = new Blob([result.file.content], {
						type: result.file.mimeType,
					});
					const url = URL.createObjectURL(blob);
					downloadDecodedFile.style.display = "inline";
					downloadDecodedFile.href = url;
					downloadDecodedFile.download = result.file.fileName;
					downloadDecodedFile.textContent = `Download Decoded File (${result.file.fileName})`;
				} else {
					downloadDecodedFile.style.display = "none";
				}
			};
			img.src = reader.result;
		};
		reader.readAsDataURL(file);
	} catch (error) {
		showMessage("An error occurred during decoding.");
	} finally {
		hideSpinner();
	}
});

document.getElementById("messageInput").addEventListener("input", () => {
	const message = messageInput.value;
	const size = new Blob([message]).size; // Size in bytes
	messageSizeSpan.textContent = size;
	updateTotalDataSize();
	updateEncodeButtonState();
});

document.getElementById("uploadFile").addEventListener("change", (event) => {
	const file = event.target.files[0];
	if (file) {
		const reader = new FileReader();
		reader.onload = () => {
			uploadedFileData = reader.result;
			const size = file.size;
			fileSizeSpan.textContent = size;
			updateTotalDataSize();
			updateEncodeButtonState();
		};
		reader.readAsArrayBuffer(file);
	} else {
		uploadedFileData = null;
		fileSizeSpan.textContent = 0;
		updateTotalDataSize();
		updateEncodeButtonState();
	}
});

document.getElementById("uploadImageWrite").addEventListener("change", () => {
	if (!uploadImageWriteInput.files.length) return;

	const file = uploadImageWriteInput.files[0];
	const reader = new FileReader();
	reader.onload = () => {
		const img = new Image();
		img.onload = () => {
			//maxDataSize = Math.floor( ( img.width * img.height * 3 ) / 8 );
			updateMaxDataSize(img);

			// Display the original image
			originalCanvas.width = img.width;
			originalCanvas.height = img.height;
			originalCtx.drawImage(img, 0, 0);

			// Clear the encoded and difference canvases
			encodedCtx.clearRect(0, 0, encodedCanvas.width, encodedCanvas.height);
			differenceCtx.clearRect(
				0,
				0,
				differenceCanvas.width,
				differenceCanvas.height
			);

			// Optionally, adjust canvas sizes
			encodedCanvas.width = img.width;
			encodedCanvas.height = img.height;
			differenceCanvas.width = img.width;
			differenceCanvas.height = img.height;

			maxBytesSpan.textContent = maxDataSize;
			updateTotalDataSize();
		};
		img.src = reader.result;
	};
	reader.readAsDataURL(file);
	updateEncodeButtonState();
});

channelRed.addEventListener("change", () => updateEncodeSettings());
channelGreen.addEventListener("change", () => updateEncodeSettings());
channelBlue.addEventListener("change", () => updateEncodeSettings());
bitDepthInput.addEventListener("input", () => updateEncodeSettings());
uploadImageReadInput.addEventListener("change", updateDecodeButtonState);
amplificationSlider.addEventListener("input", () => {
	amplificationFactor = parseInt(amplificationSlider.value);
	amplificationValue.textContent = amplificationFactor;

	// Re-render the difference image
	if (originalImageData && encodedImageData) {
		renderDifferenceImage(originalImageData, encodedImageData);
	}
});

toggleImagesButton.addEventListener("click", toggleImagesSection);
console.log("window.isSecureContext:", window.isSecureContext);
console.log("window.crypto:", window.crypto);
console.log(
	"window.crypto.subtle:",
	window.crypto ? window.crypto.subtle : null
);
updateEncodeButtonState();
updateDecodeButtonState();
