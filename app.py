import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import pyperclip

# Encrypt with auto-generated key (Fernet)
def encrypt_message(message: str) -> tuple[str, str]:
    key = Fernet.generate_key()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(message.encode()).decode()
    return encrypted, key.decode()

# Decrypt with provided key (Fernet)
def decrypt_message(encrypted_message: str, key: str) -> str:
    try:
        fernet = Fernet(key.encode())
        decrypted = fernet.decrypt(encrypted_message.encode()).decode()
        return decrypted
    except InvalidToken:
        return "❌ Invalid secret key or encrypted message."

# RSA Key Pair Generation
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return public_pem, private_pem

# RSA Encrypt Message
def rsa_encrypt(message: str, public_key_pem: str) -> str:
    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted.hex()

# RSA Decrypt Message
def rsa_decrypt(encrypted_hex: str, private_key_pem: str) -> str:
    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
        decrypted = private_key.decrypt(
            bytes.fromhex(encrypted_hex),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return decrypted.decode()
    except Exception as e:
        return f"❌ RSA Decryption Failed: {str(e)}"

# Streamlit UI
st.title("🔐 Secure Text Encoder Decoder")

option = st.radio("Select an option:", ["Encrypt a Message", "Decrypt a Message"])

# Encrypt Section
if option == "Encrypt a Message":
    user_input = st.text_area("Enter the message to encrypt")
    
    algo_option = st.selectbox("🔧 Choose Encryption Algorithm", ["Fernet (Symmetric)", "RSA (Asymmetric)"])

    if st.button("🔒 Encrypt"):
        if user_input:
            if algo_option == "Fernet (Symmetric)":
                encrypted_text, secret_key = encrypt_message(user_input)
                st.success("🔐 Encrypted with Fernet!")
                st.text("🔑 Secret Key (save this to decrypt):")
                st.code(secret_key, "text")
                st.text("📄 Encrypted Message:")
                st.code(encrypted_text, "text")
            else:
                public_key, private_key = generate_rsa_key_pair()
                encrypted_text = rsa_encrypt(user_input, public_key)
                st.success("🔐 Encrypted with RSA!")
                st.text("🔓 Public Key (share with sender):")
                st.code(public_key, language="text")
                st.text("🔐 Private Key (keep secret for decryption):")
                st.code(private_key, language="text")
                st.text("📄 Encrypted Message:")
                st.code(encrypted_text, language="text")
        else:
            st.warning("Please enter a message to encrypt.")

# Decrypt Section
elif option == "Decrypt a Message":
    encrypted_input = st.text_area("📄 Paste the Encrypted Message", height=150)
    
    algo_option = st.selectbox("🔧 Choose Decryption Algorithm", ["Fernet (Symmetric)", "RSA (Asymmetric)"])

    key_input_method = st.radio("🔑 Select Key Input Method", ["Enter Key Manually", "Upload Key File"])

    key_input = ""

    if key_input_method == "Enter Key Manually":
        if algo_option == "Fernet (Symmetric)":
            key_input = st.text_input("🔐 Enter Secret Key", type="password", placeholder="Enter your key here")
        else:
            key_input = st.text_input("🔐 Enter Private Key", type="password", placeholder="Enter your private key here")
    else:
        uploaded_file = st.file_uploader("📁 Upload Key File", type=["txt", "pem", "key"])
        if uploaded_file is not None:
            key_input = uploaded_file.read().decode("utf-8")

    if st.button("🔓 Decrypt"):
        if encrypted_input and key_input:
            if algo_option == "Fernet (Symmetric)":
                result = decrypt_message(encrypted_input, key_input)
            else:
                result = rsa_decrypt(encrypted_input, key_input)
            
            if result.startswith("❌"):
                st.error(result)
            else:
                st.success("✅ Message Decrypted:")
                st.code(result, language='text')
                if st.button("📋 Copy Decrypted Message"):
                    pyperclip.copy(result)
                    st.toast("Decrypted message copied to clipboard!")
        else:
            st.warning("⚠️ Please provide both the encrypted message and the secret/private key.")
