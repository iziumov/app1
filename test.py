import random
import ecdsa
import hashlib
import base58
import sqlite3

def generate_key():
    key = [random.randint(0, 255) for _ in range(32)]
    return key

def generate_partial_key(fixed_part, variable_bits):
    key = fixed_part + [random.randint(0, 255) for _ in range(variable_bits)]
    return key

def private_key_to_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(bytes(private_key), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return b'\x04' + vk.to_string()

def public_key_to_address(public_key):
    sha256_bpk = hashlib.sha256(public_key).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    hashed_public_key = b'\x00' + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(hashed_public_key).digest()).digest()[:4]
    address = base58.b58encode(hashed_public_key + checksum)
    return address

def create_database(db_name='bitcoin_addresses.db'):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS addresses
                      (address TEXT PRIMARY KEY, private_key TEXT)''')
    conn.commit()
    conn.close()

def add_address_to_db(private_key, address, db_name='bitcoin_addresses.db'):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO addresses (address, private_key) VALUES (?, ?)', (address, private_key))
    conn.commit()
    conn.close()

def check_address_in_db(address, db_name='bitcoin_addresses.db'):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('SELECT address FROM addresses WHERE address = ?', (address,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def get_all_addresses(db_name='bitcoin_addresses.db'):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('SELECT address, private_key FROM addresses')
    result = cursor.fetchall()
    conn.close()
    return result

def login(private_key, db_name='bitcoin_addresses.db'):
    public_key = private_key_to_public_key(bytes.fromhex(private_key))
    address = public_key_to_address(public_key)
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('SELECT address FROM addresses WHERE private_key = ?', (private_key,))
    result = cursor.fetchone()
    conn.close()
    if result and result[0] == address.decode():
        return True
    return False

# Приклад використання
fixed_part = [0] * 25
variable_bits = 7
key = generate_partial_key(fixed_part, variable_bits)
print(f"Generated key: {key}")

private_key = generate_key()
private_key_hex = ''.join(format(x, '02x') for x in private_key)
public_key = private_key_to_public_key(private_key)
address = public_key_to_address(public_key)
print(f"Address: {address.decode()}")

create_database()
add_address_to_db(private_key_hex, address.decode())

if check_address_in_db(address.decode()):
    print(f"Address {address.decode()} found in the database.")
else:
    print(f"Address {address.decode()} not found in the database.")

# Перегляд усіх ключів та адрес
all_addresses = get_all_addresses()
print("All addresses and keys in the database:")
for addr, pk in all_addresses:
    print(f"Address: {addr}, Private Key: {pk}")

# Логін по приватному ключу
login_private_key = private_key_hex  # використовуйте згенерований ключ для логіну
if login(login_private_key):
    print(f"Login successful for private key {login_private_key}")
else:
    print(f"Login failed for private key {login_private_key}")
