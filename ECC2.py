import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64
from PIL import Image
import numpy as np
import io

# Step 1: Generate ECC key pair
def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Step 2: Save ECC keys in PEM format
def save_key_pem(private_key, public_key, private_file, public_file):
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(private_file, "wb") as priv_file:
        priv_file.write(pem_private)
    with open(public_file, "wb") as pub_file:
        pub_file.write(pem_public)

# Step 3: Load image files selected via file dialog
def load_image_files():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    image_files = filedialog.askopenfilenames(
        title="Select two image files",
        filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp")]
    )
    
    if len(image_files) == 2:  # Ensure exactly two files are selected
        print(f"Images '{image_files[0]}' and '{image_files[1]}' loaded successfully.")
        return image_files  # Return file paths
    else:
        print("Please select exactly two image files.")
        return None

# Step 4: Preprocess the image, get pixel array, and hash the pixel data directly
def get_image_data(image_path, size=(256, 256)):
    with Image.open(image_path) as img:
        img = img.convert('RGB')  # Convert to RGB to ensure consistent data
        img = img.resize(size)  # Resize to fixed dimensions
        
        # Convert the image to a NumPy array
        img_array = np.array(img)
        return img_array

# Step 5: Hash the image pixel data
def get_image_hash(image_array):
    # Generate a SHA-256 hash of the image pixel data directly
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(image_array.tobytes())
    image_hash = digest.finalize()

    # Debugging: Print the Base64-encoded hash
    print(f"Image Hash (Base64 Encoded): {base64.b64encode(image_hash).decode()}")
    return image_hash

# Step 6: Sign the image hash using ECC private key
def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature)  # Return Base64-encoded signature

# Step 7: Verify the signature using ECC public key
def verify_signature(public_key, data, signature):
    try:
        public_key.verify(
            base64.b64decode(signature),
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False

# Step 8: Compare two image arrays
def compare_images(image_array_1, image_array_2):
    if np.array_equal(image_array_1, image_array_2):
        print("The two images are identical at the pixel level.")
        return True
    else:
        print("The two images are different at the pixel level.")
        return False

# Step 9: Example usage
if __name__ == "__main__":
    # Generate ECC keys
    ecc_private_key, ecc_public_key = generate_ecc_keypair()

    # Save the keys (optional)
    save_key_pem(ecc_private_key, ecc_public_key, "ecc_private.pem", "ecc_public.pem")

    # Load two image files using file dialog
    images = load_image_files()

    if images:
        # Preprocess and get pixel data for the first image
        image_data_1 = get_image_data(images[0])

        # Preprocess and get pixel data for the second image
        image_data_2 = get_image_data(images[1])

        # Compare the two images directly
        if compare_images(image_data_1, image_data_2):
            print("The images are the same; proceeding to signing and verification.")
        else:
            print("The images are different; skipping signature comparison.")
        
        # Hash and sign only if the images are identical
        if compare_images(image_data_1, image_data_2):
            # Hash the first image data
            image_hash_1 = get_image_hash(image_data_1)

            # Sign the first image hash
            signature_1 = sign_data(ecc_private_key, image_hash_1)
            print(f"Signature for image (Base64 Encoded):\n{signature_1.decode()}\n")

            # Verify the signature for the first image
            is_valid_1 = verify_signature(ecc_public_key, image_hash_1, signature_1)
            print(f"Signature valid: {is_valid_1}")
    else:
        print("Failed to load two image files.")
