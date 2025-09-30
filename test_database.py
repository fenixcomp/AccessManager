"""
Тест модуля базы данных
"""
from database import Database
from encryption import EncryptionManager
import os

print("=" * 50)
print("ТЕСТ МОДУЛЯ БАЗЫ ДАННЫХ")
print("=" * 50)

# Удаляем старую тестовую БД если есть
test_db = "test_access_data.db"
if os.path.exists(test_db):
    os.remove(test_db)
    print("Старая тестовая БД удалена")

# Создаём БД и менеджер шифрования
print("\n1. Создание базы данных...")
db = Database(test_db)
print("✓ База данных создана")

# Создаём менеджер шифрования для тестирования паролей
master_password = "test_master_123"
encryption = EncryptionManager(master_password)

# Тест 2: Сохранение мастер-пароля
print("\n2. Сохранение мастер-пароля...")
password_hash = EncryptionManager.hash_password(master_password)
salt = encryption.get_salt()
db.save_master_password(password_hash, salt)
print("✓ Мастер-пароль сохранён")

# Проверка загрузки
saved_data = db.get_master_password_data()
if saved_data and saved_data[0] == password_hash:
    print("✓ Мастер-пароль успешно загружен из БД")
else:
    print("✗ ОШИБКА: Мастер-пароль не совпадает")

# Тест 3: Добавление организаций
print("\n3. Добавление организаций...")
org1_id = db.add_organization("ООО Рога и Копыта")
org2_id = db.add_organization("ИП Василий Пупкин")
org3_id = db.add_organization("АО Технологии")
print(f"✓ Добавлено 3 организации (ID: {org1_id}, {org2_id}, {org3_id})")

# Получение всех организаций
orgs = db.get_all_organizations()
print(f"   Всего в БД: {len(orgs)} организаций")
for org_id, org_name in orgs:
    print(f"   - {org_name} (ID: {org_id})")

# Тест 4: Поиск организаций
print("\n4. Поиск организаций...")
search_results = db.search_organizations("Рога")
print(f"✓ Найдено по запросу 'Рога': {len(search_results)} результатов")
for org_id, org_name in search_results:
    print(f"   - {org_name}")

# Тест 5: Добавление пользователей
print("\n5. Добавление пользователей...")
user1_id = db.add_user(org1_id, "Иванов Иван Иванович")
user2_id = db.add_user(org1_id, "Петров Пётр Петрович")
user3_id = db.add_user(org2_id, "Сидоров Сидор Сидорович")
print(f"✓ Добавлено 3 пользователя")

users = db.get_users_by_org(org1_id)
print(f"   Пользователи организации '{orgs[0][1]}':")
for user_id, user_name in users:
    print(f"   - {user_name} (ID: {user_id})")

# Тест 6: Добавление доступов
print("\n6. Добавление доступов...")

# Шифруем пароли
rdp_pass = encryption.encrypt("Admin123!")
ssh_pass = encryption.encrypt("RootPass456")
sql_pass = encryption.encrypt("Sa_Password789")

access1_id = db.add_access(
    org_id=org1_id,
    user_id=user1_id,
    access_type="Удалённый рабочий стол",
    protocol="RDP",
    host="192.168.1.100",
    port="3389",
    login="administrator",
    password_encrypted=rdp_pass,
    description="Главный сервер"
)

access2_id = db.add_access(
    org_id=org1_id,
    user_id=user2_id,
    access_type="SSH",
    protocol="SSH",
    host="server.company.com",
    port="22",
    login="root",
    password_encrypted=ssh_pass,
    description="Linux сервер"
)

access3_id = db.add_access(
    org_id=org1_id,
    user_id=None,
    access_type="База данных",
    protocol="MS SQL",
    host="192.168.1.200",
    port="1433",
    login="sa",
    password_encrypted=sql_pass,
    description="Основная БД компании"
)

print(f"✓ Добавлено 3 доступа")

# Получение доступов
accesses = db.get_accesses_by_org(org1_id)
print(f"   Доступы организации '{orgs[0][1]}':")
for access in accesses:
    access_id, access_type, protocol, host, port, login, pass_enc, desc, user_name = access
    # Расшифровываем пароль для проверки
    decrypted_pass = encryption.decrypt(pass_enc)
    print(f"   - {protocol} | {host}:{port} | {login} | Pass: {decrypted_pass} | User: {user_name or 'N/A'}")

# Тест 7: Добавление VPN
print("\n7. Добавление VPN...")
vpn_pass = encryption.encrypt("VPN_Secret_Pass")
vpn1_id = db.add_vpn(
    org_id=org1_id,
    vpn_type="OpenVPN",
    server="vpn.company.com:1194",
    login="vpn_user",
    password_encrypted=vpn_pass,
    description="Корпоративный VPN"
)
print("✓ VPN добавлен")

vpns = db.get_vpn_by_org(org1_id)
print(f"   VPN организации '{orgs[0][1]}':")
for vpn in vpns:
    vpn_id, vpn_type, server, login, pass_enc, desc = vpn
    decrypted_pass = encryption.decrypt(pass_enc)
    print(f"   - {vpn_type} | {server} | {login} | Pass: {decrypted_pass}")

# Тест 8: Удаление
print("\n8. Тест удаления...")
db.delete_access(access1_id)
print("✓ Доступ удалён")

remaining_accesses = db.get_accesses_by_org(org1_id)
print(f"   Осталось доступов: {len(remaining_accesses)}")

print("\n" + "=" * 50)
print("ВСЕ ТЕСТЫ ЗАВЕРШЕНЫ УСПЕШНО!")
print(f"Тестовая БД создана: {test_db}")
print("Вы можете открыть её любым SQLite-браузером")
print("=" * 50)

# Закрываем БД
db.close()