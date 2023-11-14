import socket
import json
import random
import datetime
import hashlib
import sys

#handle a post request for user login
def handle_login(request_headers):
    username = request_headers.get("username")
    password = request_headers.get("password")
    
    #check if username and password are provided
    if not username:
        print("LOGIN FAILED: missing username")
        return "501 Not Implemented", "Login Failed"
    if not password:
        print("LOGIN FAILED: missing password")
        return "501 Not Implemented", "Login Failed"
    
    #check if username and password are valid
    if validate_user(username, password):
        session_id = generate_session_id()
        create_session(session_id, username)
        print(f"LOGIN SUCCESSFUL: {username}")
        return "200 OK", "Logged in!"
    else:
        print(f"LOGIN FAILED: {username}")
        return "200 OK", "Login failed!"
        
        
#validates username and password through accounts.json
def validate_user(username, password):
    accounts_file = "accounts.json"
    try:
        with open(accounts_file, "r") as f:
            accounts = json.load(f)
        if username in accounts and len(accounts[username]) == 2:
            stored_password, salt = accounts[username]
            hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
            return hashed_password == stored_password
    except (IOError, json.JSONDecodeError):
        pass
    return False

def generate_session_id():
    return hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()

#creating a session with required information for validation
def create_session(session_id, username):
    session_data = {"username": username, "timestamp": datetime.datetime.now().timestamp()}
    sessions[session_id] = session_data
    





############### IGNORE ##################
# Function to handle a GET request for file downloads
def handle_file_download(request_headers, root_directory):
    # Obtain cookies from HTTP request
    cookies = request_headers.get("Cookie")
    
    # Check if cookies are missing
    if not cookies or COOKIE_NAME not in cookies:
        return "401 Unauthorized", ""

    session_id = cookies.split("=")[1]

    # If the "sessionID" cookie exists
    if session_id in sessions:
        session_data = sessions[session_id]

        # Check if timestamp within timeout period
        if datetime.datetime.now().timestamp() - session_data["timestamp"] <= SESSION_TIMEOUT:
            # Update sessionID timestamp for the user to the current time
            session_data["timestamp"] = datetime.datetime.now().timestamp()

            # Extract username and target information
            username = session_data["username"]
            target = request_headers.get("target")

            # Check if the file exists
            file_path = f"{root_directory}/{username}/{target}"
            try:
                with open(file_path, "r") as file:
                    file_content = file.read()
                print(f"GET SUCCEEDED: {username} : {target}")
                return "200 OK", file_content
            except FileNotFoundError:
                print(f"GET FAILED: {username} : {target}")
                return "404 NOT FOUND", ""
        else:
            print(f"SESSION EXPIRED: {session_data['username']}")
            return "401 Unauthorized", ""
    else:
        print("COOKIE INVALID")
        return "401 Unauthorized", ""

# Function to start the server
def start_server(ip, port, accounts_file, session_timeout, root_directory):
    global SESSION_TIMEOUT
    SESSION_TIMEOUT = int(session_timeout)

    # Load existing sessions from a file if available
    try:
        with open("sessions.json", "r") as f:
            global sessions
            sessions = json.load(f)
    except (IOError, json.JSONDecodeError):
        sessions = {}

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, int(port)))
    server_socket.listen(1)

    print(f"Server is running on {ip}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()
        request = client_socket.recv(1024).decode("utf-8")

        method, target, _ = request.split("\r\n")[0].split(" ")

        if method == "POST" and target == "/":
            # Handle POST request and send response
            response_status, response_body = handle_login(parse_headers(request))
        elif method == "GET":
            # Handle GET request and send response
            response_status, response_body = handle_file_download(parse_headers(request), root_directory)
        else:
            response_status = "501 Not Implemented"
            response_body = ""

        response = f"HTTP/1.1 {response_status}\r\n\r\n{response_body}"
        client_socket.sendall(response.encode())
        client_socket.close()

# Function to parse headers from the HTTP request
def parse_headers(request):
    headers = {}
    lines = request.split("\r\n")[1:-2]
    for line in lines:
        key, value = line.split(": ")
        headers[key] = value
    return headers

# Function to save sessions to a file when the server is shut down
def save_sessions():
    with open("sessions.json", "w") as f:
        json.dump(sessions, f)

# Function Main
if __name__ == "__main__":
    start_server(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    save_sessions()