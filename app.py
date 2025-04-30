import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
import pyperclip

# Encrypt with auto-generated key
def encrypt_message(message: str) -> tuple[str, str]:
    key = Fernet.generate_key()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(message.encode()).decode()
    return encrypted, key.decode()

# Decrypt with provided key
def decrypt_message(encrypted_message: str, key: str) -> str:
    try:
        fernet = Fernet(key.encode())
        decrypted = fernet.decrypt(encrypted_message.encode()).decode()
        return decrypted
    except InvalidToken:
        return "❌ Invalid secret key or encrypted message."

# Streamlit UI
st.title("🔐 Secure Text Encoder Decoder")

option = st.radio("Select an option:", ["Encrypt a Message", "Decrypt a Message"])

if option == "Encrypt a Message":
    user_input = st.text_area("Enter the message to encrypt")

    if st.button("🔒 Encrypt"):
        if user_input:
            encrypted_text, secret_key = encrypt_message(user_input)
            st.success("Message Encrypted!")
            st.text("🔑 Secret Key (save this to decrypt):")
            st.code(secret_key, language='text')
            st.text("📄 Encrypted Message:")
            st.code(encrypted_text, language='text')

            col1, col2 = st.columns(2)
            if col1.button("📋 Copy Encrypted Message"):
                pyperclip.copy(encrypted_text)
                st.toast("Encrypted message copied to clipboard!")

            if col2.button("📋 Copy Secret Key"):
                pyperclip.copy(secret_key)
                st.toast("Secret key copied to clipboard!")
        else:
            st.warning("Please enter a message to encrypt.")

elif option == "Decrypt a Message":
    encrypted_input = st.text_area("Paste the encrypted message")
    key_input = st.text_input("Paste the secret key", type="password")

    if st.button("🔓 Decrypt"):
        if encrypted_input and key_input:
            result = decrypt_message(encrypted_input, key_input)
            if result.startswith("❌"):
                st.error(result)
            else:
                st.success("Message Decrypted:")
                st.code(result, language='text')
                if st.button("📋 Copy Decrypted Message"):
                    pyperclip.copy(result)
                    st.toast("Decrypted message copied to clipboard!")
        else:
            st.warning("Please provide both the encrypted message and the secret key.")
