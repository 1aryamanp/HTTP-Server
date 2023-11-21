import socket
import json
import random
import datetime
import hashlib
import sys

SESSIONS = {}

#Checks if username and password are valid
def is_valid(username, password, accounts_file):
    with open(accounts_file, "r") as file:
        accounts = json.load(file)
        if username in accounts:
            hashed_password = hashlib.sha256((password + accounts[username][1]).encode()).hexdigest()
            if hashed_password == accounts[username][0]:
                return True
    return False

#Function to handle a POST request for user login:
def handle_post_request(request, session_timeout, accounts_file):
    #Debugging ---------------------------------------------------------------------Remove later
    print(f'\r\n\r\n{request}')

    #-------------COULD MERGE THIS PART TO 1 IF-------------------------------------------Check
    # Check if "username" and "password" are present in the request
    if "username" not in request or "password" not in request:
        # If one or both fields are missing, return HTTP status code "501 Not Implemented"
        return "HTTP/1.1 501 Not Implemented\r\n\r\n"
    elif request.split()[10] == None or request.split()[12] == None:
        # Additional check for the presence of username and password
        return "HTTP/1.1 501 Not Implemented\r\n\r\n"

    # Split the request into lines and initialize username and password variables
    x = request.splitlines()
    username = None
    password = None
    
    # Extract "username" and "password" from the request
    for i in x:
        if "username" in i:
            username = i.split(":")[1].strip()
        if "password" in i:
            password = i.split(":")[1].strip()

    # Check if the provided username and password are valid
    if is_valid(username, password, accounts_file):
        # If valid, generate a session ID, create a session, and store it in SESSIONS
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
         # Log the successful login and return HTTP status code "200 OK" with a Set-Cookie header
        print(f"SERVER LOG: {datetime.datetime.now()} LOGIN SUCCESSFUL: {username} : {password}")
        return (f"HTTP/1.1 200 OK\r\nSet-Cookie: sessionID={session_id}\r\n\r\nLogged in!")
    else:
        # If username and password are not valid, log and return HTTP status code "200 OK" with login failed message
        print(f"SERVER LOG: {datetime.datetime.now()} LOGIN FAILED: {username} : {password}")
        return "HTTP/1.1 200 OK\r\n\r\nLogin failed!"

# Function to handle a GET requests for file downloads:
def handle_get_request(request, session_timeout, root_directory) -> str:
    #Debugging ----------------------------------------------------------------------------------Remove later
    print(f'\r\n\r\n{request}')
    
    #Split the request into lines
    x = request.splitlines()
    #Initialize cookies variable
    cookies = None
    
    #Extract cookies from the request
    for i in x:
        if "Cookie" in i:
            cookies = i.split(":")[1].strip()
            break
    #Extract the target from the request
    target = request.split()[1]
    
    #If cookies are missing, return HTTP status code "401 Unauthorized"
    if cookies == None:
        return "HTTP/1.1 401 Unauthorized\r\n\r\n"
    #If the "sessionID" cookie exists:
    elif "sessionID" in cookies:
        session_id = cookies.split("=")[1]
        #If session_id is missing or empty, log and return HTTP status code "401 Unauthorized"
        if session_id == None or session_id == "":
            print(f"SERVER LOG: {datetime.datetime.now()} COOKIE INVALID: {target}")
            return "HTTP/1.1 401 Unauthorized\r\n\r\n"
        #If session_id is found in SESSIONS:
        if session_id in SESSIONS:
            session = SESSIONS[session_id]
            username = session["username"]
            #If the session is not expired:
            if session["expiry"] >= datetime.datetime.now():
                session["expiry"] = datetime.datetime.now() + datetime.timedelta(seconds=session_timeout)
                try:
                    with open(f"{root_directory}{username}{target}", "r") as file:
                        print(f"SERVER LOG: {datetime.datetime.now()} GET SUCCEEDED: {username} : {target}")
                        return f"HTTP/1.1 200 OK\r\n\r\n{file.read()}"
                except FileNotFoundError:
                    print(f"SERVER LOG: {datetime.datetime.now()} GET FAILED: {username} : {target}")
                    return "HTTP/1.1 404 NOT FOUND\r\n\r\n"
            #If the session is expired, log and return HTTP status code "401 Unauthorized"
            else:
                print(f"SERVER LOG: {datetime.datetime.now()} SESSION EXPIRED: {username} : {target}")
                return "HTTP/1.1 401 Unauthorized\r\n\r\n"
        #If session_id is not found in SESSIONS, log and return HTTP status code "401 Unauthorized"
        else:
            print(f"SERVER LOG: {datetime.datetime.now()} COOKIE INVALID: {target}")
            return "HTTP/1.1 401 Unauthorized\r\n\r\n"

#Function to start the server
def start_server(ip, port, accounts_file, session_timeout, root_directory):
    #Create and bind a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, int(port)))
    server_socket.listen()
    print(f"Listening for connections on port: {port}")

    while True:
        #Accept incoming connection
        connection_socket, address = server_socket.accept()
        request = connection_socket.recv(1024).decode()
        request_method = request.split()[0]
        request_target = request.split()[1]
        http_version = request.split()[2]
        
        #If HTTP method is "POST" and request target is "/":
        if request_method == "POST" and request_target == "/":
            #Handle POST request and send response
            response = handle_post_request(request, session_timeout, accounts_file)
            connection_socket.send(response.encode())
        #If HTTP method is "GET":
        elif request_method == "GET":
            #Handle GET request and send response
            response = handle_get_request(request, session_timeout, root_directory)
            connection_socket.send(response.encode())
        #Else: Send HTTP status "501 Not Implemented"
        else:
            print("DID IT COME HERE")
            connection_socket.send("HTTP/1.1 501 Not Implemented\r\n\r\n".encode())
        
        #Close connection
        connection_socket.close()

def main():
    #If the command does not match give a error
    if len(sys.argv) != 6:
        print("Incorrect Command Should be: python3 server.py [IP] [PORT] [ACCOUNTS_FILE] [SESSION_TIMEOUT] [ROOT_DIRECTORY]")
        sys.exit(1)
    #Take in commandline argument and check if they are correct
    ip, port, accounts_file, session_timeout, root_directory = sys.argv[1:6]
    #start the server
    start_server(ip, port, accounts_file, int(session_timeout), root_directory)

if __name__ == "__main__":
    main()