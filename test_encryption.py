"""
Тест модуля шифрования
"""
from encryption import EncryptionManager

print("=" * 50)
print("ТЕСТ МОДУЛЯ ШИФРОВАНИЯ")
print("=" * 50)

# Тест 1: Создание менеджера шифрования
print("\n1. Создание менеджера с мастер-паролем...")
master_password = "test_master_pass_123"
manager = EncryptionManager(master_password)
print("✓ Менеджер создан успешно")
print(f"   Соль (первые 10 байт): {manager.get_salt()[:10]}...")

# Тест 2: Шифрование текста
print("\n2. Шифрование пароля...")
original_password = "admin:SuperSecret123!"
encrypted = manager.encrypt(original_password)
print(f"   Оригинал: {original_password}")
print(f"   Зашифровано: {encrypted[:50]}...")
print("✓ Шифрование прошло успешно")

# Тест 3: Дешифрование
print("\n3. Дешифрование пароля...")
decrypted = manager.decrypt(encrypted)
print(f"   Расшифровано: {decrypted}")
if decrypted == original_password:
    print("✓ Дешифрование прошло успешно - данные совпадают!")
else:
    print("✗ ОШИБКА: Расшифрованные данные не совпадают с оригиналом")

# Тест 4: Хеширование мастер-пароля
print("\n4. Хеширование мастер-пароля...")
hash1 = EncryptionManager.hash_password(master_password)
hash2 = EncryptionManager.hash_password(master_password)
print(f"   Хеш 1: {hash1}")
print(f"   Хеш 2: {hash2}")
if hash1 == hash2:
    print("✓ Хеши одинаковы (как и должно быть)")
else:
    print("✗ ОШИБКА: Хеши разные")

# Тест 5: Проверка с неправильным паролем
print("\n5. Попытка расшифровки с другим мастер-паролем...")
try:
    wrong_manager = EncryptionManager("wrong_password", manager.get_salt())
    wrong_decrypted = wrong_manager.decrypt(encrypted)
    print(f"✗ ОШИБКА: Удалось расшифровать с неправильным паролем: {wrong_decrypted}")
except Exception as e:
    print("✓ Корректно - с неправильным паролем расшифровать не удалось")
    print(f"   Ошибка: {str(e)[:50]}...")

# Тест 6: Шифрование нескольких паролей
print("\n6. Шифрование разных типов данных...")
test_data = {
    "RDP": "192.168.1.100:3389|administrator|Pa$$w0rd",
    "SSH": "server.com:22|root|ssh_key_here",
    "VPN": "vpn.company.com|user@company|VPN_Pass_123",
    "SQL": "localhost:1433|sa|SQLAdmin2024"
}

print("   Тест разных форматов доступов:")
for access_type, data in test_data.items():
    encrypted_data = manager.encrypt(data)
    decrypted_data = manager.decrypt(encrypted_data)
    status = "✓" if decrypted_data == data else "✗"
    print(f"   {status} {access_type}: OK")

print("\n" + "=" * 50)
print("ВСЕ ТЕСТЫ ЗАВЕРШЕНЫ")
print("=" * 50)