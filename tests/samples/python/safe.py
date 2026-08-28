import hashlib
import os
import subprocess
cursor.execute("SELECT * FROM users WHERE name=?", (user_input,))
subprocess.run(["echo", user_input], shell=False)
password = os.environ["APP_PASSWORD"]
hashlib.sha256(password.encode())
