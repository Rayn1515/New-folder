import os
from getpass import getpass
from assets import encrypt_data, decrypt_data

def encrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        original_data = f.read()

    encrypted_data = encrypt_data(original_data, password)

    with open(file_path + '.enc', 'wb') as ef:
        ef.write(encrypted_data)

    print(f"Encrypted successfully → {file_path}.enc")

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    try:
        decrypted_data = decrypt_data(encrypted_data, password)
    except Exception:
        print("Incorrect password or file is corrupted.")
        return

    original_path = file_path.replace('.enc', '') + '_decrypted'

    with open(original_path, 'wb') as df:
        df.write(decrypted_data)

    print(f"Decrypted successfully → {original_path}")

def main():
    print("File Encryptor")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Choose (1/2): ")

    file_path = input("Enter file path: ")

    if not os.path.isfile(file_path):
        print("File does not exist.")
        return

    password = getpass("Enter password: ")

    if choice == '1':
        encrypt_file(file_path, password)
    elif choice == '2':
        decrypt_file(file_path, password)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
