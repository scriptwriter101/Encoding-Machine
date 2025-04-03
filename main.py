import os
import sqlite3
from cryptography.fernet import Fernet

def create_cipher_database():
  """Creates a database to store ciphers and their keys."""
  conn = sqlite3.connect('ciphers.db')
  cursor = conn.cursor()
  cursor.execute('''
    CREATE TABLE IF NOT EXISTS ciphers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cipher_type TEXT,
      key TEXT
    )
  ''')
  conn.commit()
  conn.close()

def generate_key():
  """Generates a unique encryption key."""
  return Fernet.generate_key()

def add_cipher(cipher_type):
  """Adds a new cipher to the database."""
  conn = sqlite3.connect('ciphers.db')
  cursor = conn.cursor()
  key = generate_key()
  cursor.execute("INSERT INTO ciphers (cipher_type, key) VALUES (?, ?)", (cipher_type, key.decode()))
  conn.commit()
  conn.close()
  print(f"Cipher '{cipher_type}' added with key: {key.decode()}")

def get_cipher_key(cipher_type):
  """Retrieves the encryption key for a given cipher type."""
  conn = sqlite3.connect('ciphers.db')
  cursor = conn.cursor()
  cursor.execute("SELECT key FROM ciphers WHERE cipher_type = ?", (cipher_type,))
  result = cursor.fetchone()
  conn.close()
  if result:
    return result[0].encode()
  else:
    return None

def encrypt_data(data, cipher_type):
  """Encrypts data using the specified cipher type."""
  key = get_cipher_key(cipher_type)
  if key:
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()
  else:
    print(f"Error: Cipher '{cipher_type}' not found.")
    return None

def decrypt_data(data, cipher_type):
  """Decrypts data using the specified cipher type."""
  key = get_cipher_key(cipher_type)
  if key:
    f = Fernet(key)
    return f.decrypt(data.encode()).decode()
  else:
    print(f"Error: Cipher '{cipher_type}' not found.")
    return None

if __name__ == "__main__":
  # Create the database if it doesn't exist
  create_cipher_database() 
  while True:
    print("\nChoose an action:")
    print("1. Add a new cipher")
    print("2. Encrypt data")
    print("3. Decrypt data")
    print("4. Exit")

    choice = input("Enter your choice: ")
    if choice == '1':
      cipher_type = input("Enter cipher type: ")
      # Create the database if it doesn't exist before adding the cipher
      create_cipher_database()
      add_cipher(cipher_type)
    elif choice == '2':
      cipher_type = input("Enter cipher type: ")
      data = input("Enter data to encrypt: ")
      encrypted_data = encrypt_data(data, cipher_type)
      if encrypted_data:
        print(f"Encrypted data: {encrypted_data}")
    elif choice == '3':
      cipher_type = input("Enter cipher type: ")
      data = input("Enter data to decrypt: ")
      decrypted_data = decrypt_data(data, cipher_type)
      if decrypted_data:
        print(f"Decrypted data: {decrypted_data}")
    elif choice == '4':
      break
    else:
      print("Invalid choice. Please try again.")
