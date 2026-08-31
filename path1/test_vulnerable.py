import hashlib
import subprocess

cursor.execute("SELECT * FROM users WHERE name=" + user_input)
subprocess.run(user_input, shell=True)
password = "secret"
hashlib.md5(password.encode())
