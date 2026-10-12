#!/usr/bin/env python3
"""
SQL Injection Prevention - Parameterized Queries
Location: 02-web-application-security/sql-injection/prevention/parameterized_queries.py
"""

import sqlite3
import mysql.connector
from mysql.connector import Error
import psycopg2
from psycopg2 import sql
import hashlib
import os

class SecureDatabaseQueries:
    """
    Example class demonstrating secure database queries using parameterization
    to prevent SQL injection attacks.
    """
    
    def __init__(self, db_type='sqlite', db_name='secure_app.db'):
        self.db_type = db_type
        self.db_name = db_name
        self.connection = None

    @staticmethod
    def hash_password(password):
        """Salted scrypt hash. Plain SHA-256 is too fast to protect passwords."""
        salt = os.urandom(16)
        digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
        return f"scrypt${salt.hex()}${digest.hex()}"

    def _q(self, query):
        """Translate %s placeholders to ? for SQLite, which does not accept %s."""
        return query.replace('%s', '?') if self.db_type == 'sqlite' else query

    def connect(self):
        """Establish database connection based on type"""
        try:
            if self.db_type == 'sqlite':
                self.connection = sqlite3.connect(self.db_name)
                print("[✓] Connected to SQLite database")
                
            elif self.db_type == 'mysql':
                # Example MySQL connection (update with your credentials)
                self.connection = mysql.connector.connect(
                    host='localhost',
                    database=self.db_name,
                    user='your_user',
                    password='your_password'
                )
                print("[✓] Connected to MySQL database")
                
            elif self.db_type == 'postgresql':
                # Example PostgreSQL connection
                self.connection = psycopg2.connect(
                    host='localhost',
                    database=self.db_name,
                    user='your_user',
                    password='your_password'
                )
                print("[✓] Connected to PostgreSQL database")
                
        except Exception as e:
            print(f"[!] Database connection error: {e}")
            return False
        return True
    
    def create_users_table(self):
        """Create example users table"""
        try:
            cursor = self.connection.cursor()
            
            if self.db_type == 'sqlite':
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
            elif self.db_type == 'mysql':
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
            elif self.db_type == 'postgresql':
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
            
            self.connection.commit()
            print("[✓] Users table created successfully")
            
        except Exception as e:
            print(f"[!] Error creating table: {e}")
    
    # SECURE METHODS - Using parameterized queries
    
    def add_user_secure(self, username, email, password):
        """
        SECURE: Add a new user using parameterized query
        This prevents SQL injection by separating SQL logic from data
        """
        try:
            cursor = self.connection.cursor()
            
            # Hash the password (never store plain text passwords!)
            password_hash = self.hash_password(password)
            
            # SECURE: Using parameterized query with placeholders
            if self.db_type in ['sqlite', 'mysql']:
                query = "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)"
                cursor.execute(self._q(query), (username, email, password_hash))
            elif self.db_type == 'postgresql':
                # PostgreSQL uses %s placeholders
                query = "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)"
                cursor.execute(self._q(query), (username, email, password_hash))
            
            self.connection.commit()
            print(f"[✓] User '{username}' added successfully (ID: {cursor.lastrowid if hasattr(cursor, 'lastrowid') else 'N/A'})")
            return True
            
        except Exception as e:
            print(f"[!] Error adding user: {e}")
            self.connection.rollback()
            return False
    
    def get_user_secure(self, username):
        """
        SECURE: Retrieve user by username using parameterized query
        """
        try:
            cursor = self.connection.cursor()
            
            # SECURE: Parameterized query
            if self.db_type in ['sqlite', 'mysql', 'postgresql']:
                query = "SELECT id, username, email, created_at FROM users WHERE username = %s"
                cursor.execute(self._q(query), (username,))
            
            result = cursor.fetchone()
            
            if result:
                print(f"[✓] User found: {result}")
                return result
            else:
                print(f"[!] User '{username}' not found")
                return None
                
        except Exception as e:
            print(f"[!] Error retrieving user: {e}")
            return None
    
    def search_users_secure(self, search_term):
        """
        SECURE: Search users with partial matching using parameterized query
        """
        try:
            cursor = self.connection.cursor()
            
            # SECURE: Use parameter for the search term with LIKE
            # Note: The % wildcards are part of the parameter value, not the SQL
            search_pattern = f"%{search_term}%"
            
            query = "SELECT id, username, email FROM users WHERE username LIKE %s OR email LIKE %s"
            cursor.execute(self._q(query), (search_pattern, search_pattern))
            
            results = cursor.fetchall()
            
            print(f"[✓] Found {len(results)} user(s) matching '{search_term}':")
            for user in results:
                print(f"    - ID: {user[0]}, Username: {user[1]}, Email: {user[2]}")
            
            return results
            
        except Exception as e:
            print(f"[!] Error searching users: {e}")
            return []
    
    def update_email_secure(self, user_id, new_email):
        """
        SECURE: Update user email using parameterized query
        """
        try:
            cursor = self.connection.cursor()
            
            # SECURE: Parameterized query
            query = "UPDATE users SET email = %s WHERE id = %s"
            cursor.execute(self._q(query), (new_email, user_id))
            
            self.connection.commit()
            
            if cursor.rowcount > 0:
                print(f"[✓] Email updated for user ID {user_id}")
                return True
            else:
                print(f"[!] No user found with ID {user_id}")
                return False
                
        except Exception as e:
            print(f"[!] Error updating email: {e}")
            self.connection.rollback()
            return False
    
    def delete_user_secure(self, user_id):
        """
        SECURE: Delete user by ID using parameterized query
        """
        try:
            cursor = self.connection.cursor()
            
            # SECURE: Parameterized query
            query = "DELETE FROM users WHERE id = %s"
            cursor.execute(self._q(query), (user_id,))
            
            self.connection.commit()
            
            if cursor.rowcount > 0:
                print(f"[✓] User ID {user_id} deleted successfully")
                return True
            else:
                print(f"[!] No user found with ID {user_id}")
                return False
                
        except Exception as e:
            print(f"[!] Error deleting user: {e}")
            self.connection.rollback()
            return False
    
    # INSECURE METHODS - For demonstration only (DO NOT USE)
    
    def add_user_insecure(self, username, email, password):
        """
        INSECURE: Adding user with string concatenation (VULNERABLE TO SQL INJECTION)
        THIS IS FOR DEMONSTRATION ONLY - NEVER USE THIS APPROACH
        """
        try:
            cursor = self.connection.cursor()
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # INSECURE: String concatenation creates SQL injection vulnerability
            query = f"INSERT INTO users (username, email, password_hash) VALUES ('{username}', '{email}', '{password_hash}')"
            
            print(f"[!] INSECURE QUERY: {query}")
            
            cursor.execute(query)
            self.connection.commit()
            print(f"[!] User added using INSECURE method")
            
        except Exception as e:
            print(f"[!] Error: {e}")
    
    def demonstrate_injection_attack(self):
        """
        Demonstrate how SQL injection works (for educational purposes)
        """
        print("\n" + "="*60)
        print("SQL INJECTION DEMONSTRATION")
        print("="*60)
        
        # Example of malicious input
        malicious_username = "admin' OR '1'='1"
        malicious_email = "hacker@example.com"
        malicious_password = "anything"
        
        print("\n[!] Malicious input example:")
        print(f"    Username: {malicious_username}")
        
        print("\n[🔴] INSECURE METHOD (String Concatenation):")
        print("    This would generate a query like:")
        print(f"    SELECT * FROM users WHERE username = '{malicious_username}'")
        print("    Which becomes:")
        print("    SELECT * FROM users WHERE username = 'admin' OR '1'='1'")
        print("    This returns ALL users because '1'='1' is always true!")
        
        print("\n[🟢] SECURE METHOD (Parameterized Query):")
        print("    The query would be:")
        print("    SELECT * FROM users WHERE username = %s")
        print("    With parameter: 'admin' OR '1'='1'")
        print("    The database treats this as a literal string, not part of the SQL logic")
        print("    So it searches for a username that literally contains \"admin' OR '1'='1\"")
        print("    Which likely doesn't exist, making the attack fail")
        
        print("\n" + "="*60)
        print("KEY TAKEAWAYS:")
        print("1. Always use parameterized queries/prepared statements")
        print("2. Never concatenate user input directly into SQL strings")
        print("3. Validate and sanitize all user input")
        print("4. Use least privilege principles for database accounts")
        print("="*60)
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            print("[✓] Database connection closed")

def main():
    """Example usage of secure database queries"""
    print("""
    ╔══════════════════════════════════════════════════╗
    ║   SQL Injection Prevention - Parameterized Queries  ║
    ║                EDUCATIONAL EXAMPLE                  ║
    ╚══════════════════════════════════════════════════╝
    """)
    
    # Initialize secure database handler
    db = SecureDatabaseQueries(db_type='sqlite', db_name='secure_app.db')
    
    if db.connect():
        # Create table
        db.create_users_table()
        
        # Add users securely
        print("\n" + "-"*40)
        print("ADDING USERS SECURELY")
        print("-"*40)
        
        db.add_user_secure("alice", "alice@example.com", "SecurePass123!")
        db.add_user_secure("bob", "bob@example.com", "AnotherPass456!")
        db.add_user_secure("charlie", "charlie@example.com", "CharliePass789!")
        
        # Retrieve users
        print("\n" + "-"*40)
        print("RETRIEVING USERS SECURELY")
        print("-"*40)
        
        db.get_user_secure("alice")
        
        # Search users
        print("\n" + "-"*40)
        print("SEARCHING USERS SECURELY")
        print("-"*40)
        
        db.search_users_secure("alice")
        
        # Update user
        print("\n" + "-"*40)
        print("UPDATING USER SECURELY")
        print("-"*40)
        
        db.update_email_secure(1, "alice.new@example.com")
        
        # Demonstrate SQL injection concept
        db.demonstrate_injection_attack()
        
        # Close connection
        db.close()
    
    print("\n" + "="*60)
    print("✅ SECURE CODING PRACTICES IMPLEMENTED:")
    print("• Parameterized queries for all database operations")
    print("• Password hashing (never stored in plaintext)")
    print("• Proper error handling")
    print("• Input validation (implicitly through parameterization)")
    print("="*60)

if __name__ == "__main__":
    main()
