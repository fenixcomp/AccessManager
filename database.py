"""
Модуль для работы с базой данных SQLite
"""
import sqlite3
from typing import List, Tuple, Optional
import os


class Database:
    """Управление базой данных"""
    
    def __init__(self, db_path: str = "access_data.db"):
        """
        Инициализация подключения к БД
        
        Args:
            db_path: Путь к файлу базы данных
        """
        self.db_path = db_path
        self.connection = None
        self.cursor = None
        self._connect()
        self._create_tables()
    
    def _connect(self):
        """Подключение к базе данных"""
        self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
        self.cursor = self.connection.cursor()
    
    def _create_tables(self):
        """Создание таблиц БД если их нет"""
        # Таблица для хранения мастер-пароля и соли
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY,
                master_password_hash TEXT NOT NULL,
                salt BLOB NOT NULL
            )
        """)
        
        # Таблица организаций
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        """)
        
        # Таблица пользователей
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
            )
        """)
        
        # Таблица доступов
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS accesses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                user_id INTEGER,
                access_type TEXT NOT NULL,
                protocol TEXT NOT NULL,
                host TEXT,
                port TEXT,
                login TEXT,
                password_encrypted TEXT,
                description TEXT,
                FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        
        # Таблица VPN
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS vpn (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                vpn_type TEXT NOT NULL,
                server TEXT,
                login TEXT,
                password_encrypted TEXT,
                description TEXT,
                FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
            )
        """)
        
        self.connection.commit()
    
    # === НАСТРОЙКИ ===
    def save_master_password(self, password_hash: str, salt: bytes):
        """Сохранить хеш мастер-пароля и соль"""
        self.cursor.execute("DELETE FROM settings")
        self.cursor.execute(
            "INSERT INTO settings (id, master_password_hash, salt) VALUES (1, ?, ?)",
            (password_hash, salt)
        )
        self.connection.commit()
    
    def get_master_password_data(self) -> Optional[Tuple[str, bytes]]:
        """Получить хеш мастер-пароля и соль"""
        self.cursor.execute("SELECT master_password_hash, salt FROM settings WHERE id = 1")
        result = self.cursor.fetchone()
        return result if result else None
    
    # === ОРГАНИЗАЦИИ ===
    def add_organization(self, name: str) -> int:
        """Добавить организацию"""
        self.cursor.execute("INSERT INTO organizations (name) VALUES (?)", (name,))
        self.connection.commit()
        return self.cursor.lastrowid
    
    def get_all_organizations(self) -> List[Tuple[int, str]]:
        """Получить все организации"""
        self.cursor.execute("SELECT id, name FROM organizations ORDER BY name")
        return self.cursor.fetchall()
    
    def search_organizations(self, query: str) -> List[Tuple[int, str]]:
        """Поиск организаций"""
        self.cursor.execute(
            "SELECT id, name FROM organizations WHERE name LIKE ? ORDER BY name",
            (f"%{query}%",)
        )
        return self.cursor.fetchall()
    
    def delete_organization(self, org_id: int):
        """Удалить организацию"""
        self.cursor.execute("DELETE FROM organizations WHERE id = ?", (org_id,))
        self.connection.commit()
    
    # === ПОЛЬЗОВАТЕЛИ ===
    def add_user(self, org_id: int, name: str) -> int:
        """Добавить пользователя"""
        self.cursor.execute(
            "INSERT INTO users (org_id, name) VALUES (?, ?)",
            (org_id, name)
        )
        self.connection.commit()
        return self.cursor.lastrowid
    
    def get_users_by_org(self, org_id: int) -> List[Tuple[int, str]]:
        """Получить пользователей организации"""
        self.cursor.execute(
            "SELECT id, name FROM users WHERE org_id = ? ORDER BY name",
            (org_id,)
        )
        return self.cursor.fetchall()
    
    def delete_user(self, user_id: int):
        """Удалить пользователя"""
        self.cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        self.connection.commit()
    
    # === ДОСТУПЫ ===
    def add_access(self, org_id: int, user_id: Optional[int], access_type: str,
                   protocol: str, host: str, port: str, login: str,
                   password_encrypted: str, description: str = "") -> int:
        """Добавить доступ"""
        self.cursor.execute("""
            INSERT INTO accesses 
            (org_id, user_id, access_type, protocol, host, port, login, password_encrypted, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (org_id, user_id, access_type, protocol, host, port, login, password_encrypted, description))
        self.connection.commit()
        return self.cursor.lastrowid
    
    def get_accesses_by_org(self, org_id: int) -> List[Tuple]:
        """Получить все доступы организации"""
        self.cursor.execute("""
            SELECT a.id, a.access_type, a.protocol, a.host, a.port, a.login, 
                   a.password_encrypted, a.description, u.name as user_name
            FROM accesses a
            LEFT JOIN users u ON a.user_id = u.id
            WHERE a.org_id = ?
            ORDER BY a.access_type, a.protocol
        """, (org_id,))
        return self.cursor.fetchall()
    
    def get_accesses_by_user(self, user_id: int) -> List[Tuple]:
        """Получить доступы пользователя"""
        self.cursor.execute("""
            SELECT id, access_type, protocol, host, port, login, 
                   password_encrypted, description
            FROM accesses
            WHERE user_id = ?
            ORDER BY access_type, protocol
        """, (user_id,))
        return self.cursor.fetchall()
    
    def delete_access(self, access_id: int):
        """Удалить доступ"""
        self.cursor.execute("DELETE FROM accesses WHERE id = ?", (access_id,))
        self.connection.commit()
    
    # === VPN ===
    def add_vpn(self, org_id: int, vpn_type: str, server: str, login: str,
                password_encrypted: str, description: str = "") -> int:
        """Добавить VPN"""
        self.cursor.execute("""
            INSERT INTO vpn (org_id, vpn_type, server, login, password_encrypted, description)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (org_id, vpn_type, server, login, password_encrypted, description))
        self.connection.commit()
        return self.cursor.lastrowid
    
    def get_vpn_by_org(self, org_id: int) -> List[Tuple]:
        """Получить VPN организации"""
        self.cursor.execute("""
            SELECT id, vpn_type, server, login, password_encrypted, description
            FROM vpn
            WHERE org_id = ?
            ORDER BY vpn_type
        """, (org_id,))
        return self.cursor.fetchall()
    
    def delete_vpn(self, vpn_id: int):
        """Удалить VPN"""
        self.cursor.execute("DELETE FROM vpn WHERE id = ?", (vpn_id,))
        self.connection.commit()
    
    def close(self):
        """Закрыть соединение с БД"""
        if self.connection:
            self.connection.close()