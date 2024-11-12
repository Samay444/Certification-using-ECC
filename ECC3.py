import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64
from email import message_from_binary_file
from bs4 import BeautifulSoup
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

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

# Step 3: Load any file (image or HTML/MHTML)
# Step 3: Load any file (image, HTML, or MHTML)
def load_file():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    file_path = filedialog.askopenfilename(
        title="Select a file",
        filetypes=[("HTML and MHTML Files", "*.html;*.htm;*.mhtml"), ("All Files", "*.*")]
    )
    return file_path


# Step 4: Extract and clean HTML text
def get_text_from_html(file_path):
    with open(file_path, 'r', encoding="utf-8") as file:
        soup = BeautifulSoup(file, "html.parser")
        text = soup.get_text(separator=' ', strip=True)
        return text.lower()  # Convert text to lowercase for uniformity

# Step 5: Extract and clean MHTML text
def get_text_from_mhtml(file_path):
    with open(file_path, 'rb') as f:
        msg = message_from_binary_file(f)
        content = ""
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                content += part.get_payload(decode=True).decode()
    soup = BeautifulSoup(content, "html.parser")
    text = soup.get_text(separator=' ', strip=True)
    return text.lower()

# Step 6: Compare HTML or MHTML documents for similarity
def compare_documents(text1, text2):
    vectorizer = TfidfVectorizer()
    tfidf_matrix = vectorizer.fit_transform([text1, text2])
    similarity_score = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]
    print(f"Similarity Score: {similarity_score:.2f}")
    return similarity_score

# Step 7: Example usage
if __name__ == "__main__":
    # Generate ECC keys
    ecc_private_key, ecc_public_key = generate_ecc_keypair()
    save_key_pem(ecc_private_key, ecc_public_key, "ecc_private.pem", "ecc_public.pem")

    # Load first file
    print("Select the first HTML or MHTML file to compare.")
    file_path1 = load_file()
    if not file_path1:
        print("No file selected.")
        exit()

    # Load second file
    print("Select the second HTML or MHTML file to compare.")
    file_path2 = load_file()
    if not file_path2:
        print("No file selected.")
        exit()

    # Normalize extensions and load content
    ext1, ext2 = os.path.splitext(file_path1)[1].lower(), os.path.splitext(file_path2)[1].lower()
    if ext1 in ('.html', '.htm') and ext2 in ('.html', '.htm'):
        text1 = get_text_from_html(file_path1)
        text2 = get_text_from_html(file_path2)
    elif ext1 == '.mhtml' and ext2 == '.mhtml':
        text1 = get_text_from_mhtml(file_path1)
        text2 = get_text_from_mhtml(file_path2)
    elif ext1 in ('.html', '.htm') and ext2 == '.mhtml':
        text1 = get_text_from_html(file_path1)
        text2 = get_text_from_mhtml(file_path2)
    elif ext1 == '.mhtml' and ext2 in ('.html', '.htm'):
        text1 = get_text_from_mhtml(file_path1)
        text2 = get_text_from_html(file_path2)
    else:
        print("Unsupported file types.")
        exit()

    # Compare documents
    similarity_score = compare_documents(text1, text2)
    if similarity_score > 0.9:
        print("The documents are Original.")
    elif similarity_score > 0.5:
        print("The documents are Tempered.")
    else:
        print("The documents are Forged.")
