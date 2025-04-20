import sys, os, string, secrets, re
from termcolor import colored
from flask_bcrypt import Bcrypt
from flask import Flask
from dotenv import load_dotenv

app = Flask(__name__)
bcrypt = Bcrypt(app)
first_run = not os.path.isdir("./prod/postgres_data")




def println(data, color, background='', atr=[], end='\n'):
    if background == '' and atr == []:
        print(colored(data, color), end=end)
    elif background != '' and atr == []:
        print(colored(data, color, background), end=end)
    elif background == '' and atr != []:
        print(colored(data, color, attrs=atr), end=end)
    else:
        print(colored(data, color, background, attrs=atr), end=end)


def gen_password(length):
    """Generate a password containing only English letters and numbers"""
    characters = string.ascii_letters + string.digits
    while True:
        password = ''.join(secrets.choice(characters) for _ in range(length))
        # Ensure password contains at least one letter and one number
        if any(c.isalpha() for c in password) and any(c.isdigit() for c in password):
            return password


def start_palantir():
    flag = os.system("nohup docker compose -f ./prod/docker-compose.yml up --build &>> /dev/null")
    if flag == 0:
        println("[+] Palantir was started successfully", "green")
    else:
        println("[-] Some problems encountered while starting palantir. Try again with root permissions and from main palantir's directory", "red")


def purge_db():
    stop_palantir(silence=True)
    flag = os.system("nohup rm -rf ./prod/postgres_data &>> /dev/null")
    if flag == 0:
        println("[+] Database was purged successfully", "green")
    else:
        println("[-] Some problems encountered while purging db. Try again with root permissions and from main palantir's directory", "red")


def stop_palantir(silence=False):
    flag = os.system("nohup docker compose -f ./prod/docker-compose.yml down &>> /dev/null")
    if not silence:
        if flag == 0:
            println("[+] Palantir was stopped successfully", "green")
        else:
            println("[-] Some problems encountered while stopping palantir. Try again with root permissions and from main palantir's directory", "red")


def update_env_file(env_vars):
    """Update or create .env file with new variables"""
    env_path = "./prod/.env"
    
    # Read existing .env file if it exists
    existing_vars = {}
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    key, value = line.strip().split("=", 1)
                    existing_vars[key] = value
    
    # Update with new variables
    existing_vars.update(env_vars)
    
    # Write back to .env file
    with open(env_path, "w") as f:
        for key, value in existing_vars.items():
            f.write(f"{key}={value}\n")


def set_options():
    # Generate secure credentials
    db_username = gen_password(16)
    db_password = gen_password(24)
    registry_username = gen_password(16)
    registry_password = gen_password(24)
    
    # Get user credentials
    ans = input(colored("[!] Enter user:password for basic palantir user, or just press enter to choose random generated creds: ", "magenta"))
    
    if ans.strip() == '':
        username = "melkor"
        password = gen_password(24)
    else:
        ans = list(ans.strip().split(":"))
        username, password = ans
    
    # Update .env file
    env_vars = {
        "DB_USERNAME": db_username,
        "DB_PASSWORD": db_password,
        "REGISTRY_USERNAME": registry_username,
        "REGISTRY_PASSWORD": registry_password
    }
    update_env_file(env_vars)
    
    # Update configuration files
    def edit_file(file_name, regex, replacement):
        with open(file_name, "r", encoding="utf-8") as file:
            content = file.read()
        updated_content = re.sub(regex, replacement, content)
        with open(file_name, "w", encoding='utf-8') as file:
            file.write(updated_content)
    
    # Update docker-compose.yml to use environment variables
    edit_file("./prod/docker-compose.yml", r"(POSTGRES_USER:\s*)(.*)", r'\1${DB_USERNAME}')
    edit_file("./prod/docker-compose.yml", r"(POSTGRES_PASSWORD:\s*)(.*)", r'\1${DB_PASSWORD}')
    
    # Update database initialization script
    hash = bcrypt.generate_password_hash(password).decode("utf-8")
    edit_file("./prod/web/db_init_stuff/init.sql", r"VALUES \('.*?', '.*?', '(.*?)'\)", rf"VALUES ('{username}', '{hash}', '\1')")
    edit_file("./prod/web/db_init_stuff/start.sh", r'PGPASSWORD="(.*?)"\spsql\s-U\s"(.*?)"', rf'PGPASSWORD="{db_password}" psql -U "{db_username}"')




try:
    action = sys.argv[1] # start/stop/clean_start/purge_db
except:
    println("[-] The program should be started with one of several options chosen: start/stop/clean_start/purge_db", "red")
    sys.exit()

if not os.path.isdir("./prod/dckesc"):
    println("[-] The program should be started from the main project directory", "red")
    sys.exit()

println("[!] Welcome to dckesc control system!", "magenta")
match action:
    case "start":
        if first_run:
            set_options()
        start_palantir()
    case "stop":
        stop_palantir()
    case "purge_db":
        if not first_run:
            stop_palantir()
            purge_db()
        else:
            println("[!] You already haven't database", "magenta")
    case "clean_start":
        if not first_run:
            stop_palantir()
            purge_db()
        set_options()
        start_palantir()
    case _:
        println("[-] The program should be started with one of several options chosen: start/stop/clean_start/purge_db", "red")
