import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv
load_dotenv()

# Ключ из .env
FERNET_KEY = os.getenv("FERNET_KEY")
FERNET_KEY = FERNET_KEY.strip()

cipher = Fernet(FERNET_KEY.encode())

# Имя файла
filename = "ВСТАВЬТЕ НАЗВАНИЕ ФАЙЛА ЗДЕСЬ"

with open(filename, "rb") as f:
    encrypted_data = f.read()

decrypted = cipher.decrypt(encrypted_data)
print(decrypted.decode('utf-8'))