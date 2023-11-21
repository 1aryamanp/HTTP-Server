import socket
import json
import random
import datetime
import hashlib
import sys

SESSIONS = {}

def is_valid(username, password, accounts_file):
    with open(accounts_file, "r") as file:
        accounts = json.load(file)
        if username in accounts:
            hashed_password = hashlib.sha256((password + accounts[username][1]).encode()).hexdigest()
            if hashed_password == accounts[username][0]:
                return True
    return False

def handle_post_request(request, session_timeout, accounts_file):
    print(f'\r\n\r\n{request}')

    if "username" not in request or "password" not in request:
        return "HTTP/1.1 501 Not Implemented\r\n\r\n"
    elif request.split()[10] == None or request.split()[12] == None:
        return "HTTP/1.1 501 Not Implemented\r\n\r\n"

    x = request.splitlines()
    username = None
    password = None
    for i in x:
        if "username" in i:
            username = i.split(":")[1].strip()
        if "password" in i:
            password = i.split(":")[1].strip()

    if is_valid(username, password, accounts_file):
        session_id = hex(random.randint(0, 2**64))
        host = request.split()[4]
        session = {
            "host": host,
            "session_id": session_id,
            "username": username,
            "password": password,
            "expiry": datetime.datetime.now() + datetime.timedelta(seconds=session_timeout),
        }
        SESSIONS[session_id] = session
        print(f"SERVER LOG: {datetime.datetime.now()} LOGIN SUCCESSFUL: {username} : {password}")
        return (f"HTTP/1.1 200 OK\r\nSet-Cookie: sessionID={session_id}\r\n\r\nLogged in!")
    else:
        print(f"SERVER LOG: {datetime.datetime.now()} LOGIN FAILED: {username} : {password}")
        return "HTTP/1.1 200 OK\r\n\r\nLogin failed!"

def handle_get_request(request, session_timeout, root_directory) -> str:
    print(f'\r\n\r\n{request}')
    x = request.splitlines()
    cookies = None
    for i in x:
        if "Cookie" in i:
            cookies = i.split(":")[1].strip()
            break
    target = request.split()[1]
    if cookies == None:
        return "HTTP/1.1 401 Unauthorized\r\n\r\n"
    elif "sessionID" in cookies:
        session_id = cookies.split("=")[1]
        if session_id == None or session_id == "":
            print(f"SERVER LOG: {datetime.datetime.now()} COOKIE INVALID: {target}")
            return "HTTP/1.1 401 Unauthorized\r\n\r\n"
        if session_id in SESSIONS:
            session = SESSIONS[session_id]
            username = session["username"]
            if session["expiry"] >= datetime.datetime.now():
                session["expiry"] = datetime.datetime.now() + datetime.timedelta(seconds=session_timeout)
                try:
                    with open(f"{root_directory}{username}{target}", "r") as file:
                        print(f"SERVER LOG: {datetime.datetime.now()} GET SUCCEEDED: {username} : {target}")
                        return f"HTTP/1.1 200 OK\r\n\r\n{file.read()}"
                except FileNotFoundError:
                    print(f"SERVER LOG: {datetime.datetime.now()} GET FAILED: {username} : {target}")
                    return "HTTP/1.1 404 NOT FOUND\r\n\r\n"
            else:
                print(f"SERVER LOG: {datetime.datetime.now()} SESSION EXPIRED: {username} : {target}")
                return "HTTP/1.1 401 Unauthorized\r\n\r\n"
        else:
            print(f"SERVER LOG: {datetime.datetime.now()} COOKIE INVALID: {target}")
            return "HTTP/1.1 401 Unauthorized\r\n\r\n"

def start_server(ip, port, accounts_file, session_timeout, root_directory):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, int(port)))
    server_socket.listen()
    print(f"Listening for connections on port {port}...")

    while True:
        connection_socket, address = server_socket.accept()
        request = connection_socket.recv(1024).decode()
        request_method = request.split()[0]
        request_target = request.split()[1]
        http_version = request.split()[2]
        if request_method == "POST" and request_target == "/":
            response = handle_post_request(request, session_timeout, accounts_file)
            connection_socket.send(response.encode())
        elif request_method == "GET":
            response = handle_get_request(request, session_timeout, root_directory)
            connection_socket.send(response.encode())
        else:
            connection_socket.send("HTTP/1.1 501 Not Implemented\r\n\r\n".encode())
        connection_socket.close()

def main():
    if len(sys.argv) != 6:
        print("Usage: python3 server.py [IP] [PORT] [ACCOUNTS_FILE] [SESSION_TIMEOUT] [ROOT_DIRECTORY]")
        sys.exit(1)
    ip, port, accounts_file, session_timeout, root_directory = sys.argv[1:6]
    start_server(ip, port, accounts_file, int(session_timeout), root_directory)

if __name__ == "__main__":
    main()
