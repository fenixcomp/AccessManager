"""
Модуль для шифрования и дешифрования паролей с использованием AES-256
"""
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64


class EncryptionManager:
    """Управление шифрованием паролей"""
    
    def __init__(self, master_password: str, salt: bytes = None):
        """
        Инициализация менеджера шифрования
        
        Args:
            master_password: Мастер-пароль для шифрования
            salt: Соль для генерации ключа (если None, создаётся новая)
        """
        if salt is None:
            import os
            self.salt = os.urandom(16)
        else:
            self.salt = salt
            
        # Создаём ключ из мастер-пароля
        self.key = self._derive_key(master_password, self.salt)
        self.cipher = Fernet(self.key)
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Генерация ключа шифрования из пароля
        
        Args:
            password: Мастер-пароль
            salt: Соль
            
        Returns:
            Ключ шифрования в формате base64
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt(self, text: str) -> str:
        """
        Шифрование текста
        
        Args:
            text: Исходный текст
            
        Returns:
            Зашифрованный текст в base64
        """
        if not text:
            return ""
        encrypted = self.cipher.encrypt(text.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_text: str) -> str:
        """
        Дешифрование текста
        
        Args:
            encrypted_text: Зашифрованный текст в base64
            
        Returns:
            Расшифрованный текст
        """
        if not encrypted_text:
            return ""
        try:
            encrypted = base64.urlsafe_b64decode(encrypted_text.encode())
            decrypted = self.cipher.decrypt(encrypted)
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"Ошибка дешифрования: {str(e)}")
    
    def get_salt(self) -> bytes:
        """Получить соль для сохранения"""
        return self.salt
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Хеширование мастер-пароля для проверки
        
        Args:
            password: Пароль для хеширования
            
        Returns:
            SHA-256 хеш пароля
        """
        return hashlib.sha256(password.encode()).hexdigest()


# Пример использования (для тестирования)
if __name__ == "__main__":
    # Создаём менеджер шифрования с мастер-паролем
    manager = EncryptionManager("мой_супер_пароль_123")
    
    # Шифруем
    original = "admin:password123"
    encrypted = manager.encrypt(original)
    print(f"Оригинал: {original}")
    print(f"Зашифровано: {encrypted}")
    
    # Дешифруем
    decrypted = manager.decrypt(encrypted)
    print(f"Расшифровано: {decrypted}")
    
    # Проверяем хеш мастер-пароля
    hash_value = EncryptionManager.hash_password("мой_супер_пароль_123")
    print(f"Хеш мастер-пароля: {hash_value}")