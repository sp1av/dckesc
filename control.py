import sys, os, string, secrets, re
from termcolor import colored
from flask_bcrypt import Bcrypt
from flask import Flask

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


def gen_string(length):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))


def start_palantir():
    flag = os.system("nohup docker compose -f ./prod/docker-compose.yml up --build &>> /dev/null")
    if flag == 0:
        println("[+] Palantir was started successfully", "green")
    else:
        println("[-] Some problems encouraged while starting palantir. Try again with root permissions and from main palantir`s directory ","red")


def purge_db():
    stop_palantir(silence=True)
    flag = os.system("nohup rm -rf ./prod/postgres_data &>> /dev/null")
    if flag == 0:
        println("[+] Database was purged successfully", "green")
    else:
        println("[-] Some problems encouraged while purging db. Try again with root permissions and from main palantir`s directory ","red")


def stop_palantir(silence=False):
    flag = os.system("nohup docker compose -f ./prod/docker-compose.yml down &>> /dev/null")
    if not silence:
        if flag == 0:
            println("[+] Palantir was stopped successfully", "green")
        else:
            println( "[-] Some problems encouraged while stopping palantir. Try again with root permissions and from main palantir`s directory ","red")


def set_options():
    def edit_file(file_name, regex, replacement):
        with open(file_name, "r", encoding="utf-8") as file:
            content = file.read()
        updated_content = re.sub(regex, replacement, content)
        with open(file_name, "w", encoding='utf-8') as file:
            file.write(updated_content)

    db_username = gen_string(27)
    db_password = gen_string(27)
    ans = input(colored("[!] Enter user:password for basic palantir user, or just press enter to choose random generated creds: ", "magenta"))

    if ans.strip() == '':
        username = "melkor"
        password = gen_string(27)
    else:
        ans = list(ans.strip().split(":"))
        username, password = ans

    edit_file("./prod/docker-compose.yml", r"(POSTGRES_USER:\s*)(.*)", fr'\1{db_username}')
    edit_file("./prod/docker-compose.yml", r"(POSTGRES_PASSWORD:\s*)(.*)", fr'\1{db_password}')
    edit_file("./prod/dckesc/config.py",  r"(postgresql://)([^:]+):([^@]+)(@postgres:\d+/)", rf"\1{db_username}:{db_password}\4")
    edit_file("./prod/web/config.py",  r"(postgresql://)([^:]+):([^@]+)(@postgres:\d+/)", rf"\1{db_username}:{db_password}\4")
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
            println("[!] You already haven`t database", "magenta")
    case "clean_start":
        if not first_run:
            stop_palantir()
            purge_db()
        set_options()
        start_palantir()
    case _:
        println("[-] The program should be started with one of several options chosen: start/stop/clean_start/purge_db", "red")
