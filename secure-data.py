import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import base64
import json
import os

DATA_FILE = "encrypted_data.json"

# Load data from file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {"data_store": {}, "login_attempts": {}}

# Save data to file
def save_data(data_store, login_attempts):
    with open(DATA_FILE, "w") as f:
        json.dump({"data_store": data_store, "login_attempts": login_attempts}, f)

# Key generation using SHA256
def generate_key(passkey: str) -> bytes:
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

# Encrypt data
def encrypt_data(data: str, passkey: str) -> str:
    key = generate_key(passkey)
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

# Decrypt data
def decrypt_data(token: str, passkey: str) -> str:
    key = generate_key(passkey)
    f = Fernet(key)
    return f.decrypt(token.encode()).decode()

# Load from file at app start
data_loaded = load_data()
data_store = data_loaded["data_store"]
login_attempts = data_loaded["login_attempts"]

# Streamlit UI
st.title("🔐 Secure Data Encryption System")

menu = st.sidebar.radio("Menu", ["Store Data", "Retrieve Data", "Reset System"])

# Store Data
if menu == "Store Data":
    st.header("📥 Store Your Secure Data")
    username = st.text_input("Enter Username")
    passkey = st.text_input("Enter Passkey", type="password")
    data = st.text_area("Enter Data to Encrypt")

    if st.button("Encrypt & Save"):
        if username and passkey and data:
            encrypted = encrypt_data(data, passkey)
            data_store[username] = encrypted
            login_attempts[username] = 0
            save_data(data_store, login_attempts)
            st.success("✅ Data encrypted and saved!")
        else:
            st.warning("⚠️ Please fill all fields.")

# Retrieve Data
elif menu == "Retrieve Data":
    st.header("🔓 Retrieve Your Secure Data")
    username = st.text_input("Enter Username")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt & Retrieve"):
        if username in data_store:
            if login_attempts.get(username, 0) >= 3:
                st.error("❌ Too many failed attempts. Please reauthorize.")
                st.stop()

            try:
                decrypted = decrypt_data(data_store[username], passkey)
                st.success("✅ Data decrypted successfully!")
                st.text_area("Your Data:", decrypted, height=150)
                login_attempts[username] = 0
            except:
                login_attempts[username] = login_attempts.get(username, 0) + 1
                st.error(f"❌ Incorrect passkey. Attempt {login_attempts[username]}/3")
            save_data(data_store, login_attempts)
        else:
            st.error("❌ No data found for this username.")

# Reset System
elif menu == "Reset System":
    st.header("🗑️ Reset In-Memory & File Storage")
    if st.button("Clear All Data"):
        data_store.clear()
        login_attempts.clear()
        save_data(data_store, login_attempts)
        st.success("✅ All data cleared from memory and file.")
