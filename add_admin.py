import sqlite3

DB = 'mascotas.db'
email_admin = input("Ingresa el email del usuario a hacer admin: ").strip()

conn = sqlite3.connect(DB)
conn.execute('UPDATE users SET admin = 1 WHERE email = ?', (email_admin,))
conn.commit()
conn.close()

print(f"Usuario {email_admin} actualizado a admin.")
