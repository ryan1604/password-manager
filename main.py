import json
import os
import maskpass
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def run():
    global passwords, key
    if not os.path.exists("data"):
        os.mkdir("data")
    
    if not os.path.exists("data/data.json"):
        passwords = {}
    else:
        with open("data/data.json") as f:
            passwords = json.load(f)

    if not os.path.exists("data/salt.key"):
        salt = os.urandom(16)
        print(salt)
        with open("data/salt.key", "wb") as f:
            f.write(salt)
    else:
        with open("data/salt.key", "rb") as f:
            salt = f.read()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )

    master_pw = maskpass.askpass(prompt="Enter master password: ", mask="")
    key = base64.urlsafe_b64encode(kdf.derive(master_pw.encode()))

    exit_program = False

    while not exit_program:
        user_input = input("Enter a command or type 'help' for more info: ")
        user_input = user_input.split(" ")

        exit_program = parse_input(user_input)

def parse_input(user_input):
    match user_input[0].lower():
        case "add":
            try:
                check_and_add(user_input)
            except Exception as e:
                print(e)
        case "view":
            view()
        case "quit":
            save()
            return True
        case "help":
            help()
        case _:
            print("Unknown command. Type 'help' for more info.")

def check_and_add(user_input):
    if len(user_input) < 3:
        raise Exception("Missing parameters in command. Should be 'add username password'.")
    if (user_input[1] == "master"):
        raise Exception("'master' cannot be used as username.")
    
    f = Fernet(key)
    passwords[user_input[1]] = f.encrypt(user_input[2].encode()).decode()
    print("Username and password successfully added.")

def view():
    f = Fernet(key)
    print("Here are your passwords:")
    for username, password in passwords.items():
        if username == "master":
            continue
        print(f"username: {username}, password: {f.decrypt(password).decode()}")

def save():
    with open("data/data.json", "w") as f:
        json.dump(passwords, f, indent=4)

def help():
    print("Here are the available commands:")
    print("add: Add an entry with the format 'add username password'.")
    print("view: View all accounts and their passwords.")
    print("quit: Quit the program.")
    print("help: List all commands and their usage.")

if __name__ == "__main__":
    run()