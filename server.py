import socket
import json
import random
import datetime
import hashlib
import sys

# Constants IDK why we need this-----------------------------------------------------------------------CHECK
COOKIE_NAME = "sessionID"

#Function to handle a POST request for user login:
def handle_login(request_headers):
    #Obtain username and password from request headers
    username = request_headers.get("username")
    password = request_headers.get("password")

    #If 1 or both fields missing:
    if not username or not password:
        print("LOGIN FAILED: missing username or password")
        return "501 Not Implemented", "Login Failed"
    
    #If username and password are valid:
    # Check if username and password are valid
    if validate_user(username, password):
        # Set a cookie called "sessionID" to a random 64-bit hexadecimal value
        session_id = hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()
        # Create a session with required info for validation using the cookie
        create_session(session_id, username)
        # Log with MESSAGE "LOGIN SUCCESSFUL: {username} : {password}"
        print(f"LOGIN SUCCESSFUL: {username} : {password}")
        # Return HTTP 200 OK response with body "Logged in!"
        return "200 OK", "Logged in!"
    else:
        # Log with MESSAGE "LOGIN FAILED: {username} : {password}
        print(f"LOGIN FAILED: {username} : {password}")
        # Return HTTP 200 OK response with body "Login failed!"
        return "200 OK", "Login failed!"

#Function to handle a GET requests for file downloads:
def handle_file_download(request_headers, root_directory):
    # Obtain cookies from HTTP request
    cookies = request_headers.get("Cookie")
    # Check if cookies are missing, Return HTTP status code "401 Unauthorized"
    if not cookies or COOKIE_NAME not in cookies:
        return "401 Unauthorized"
    #IDK why do we need this--------------------------------------------------------------------------CHECK
    session_id = cookies.split("=")[1]
    # If the "sessionID" cookie exists
    if session_id in sessions:
        session_data = sessions[session_id]
        # Get username and timestamp information for that sessionID
        username = session_data.get("username")
        timestamp = session_data.get("timestamp")
        # If timestamp within timeout period
        if timestamp and datetime.datetime.now().timestamp() - timestamp <= SESSION_TIMEOUT:
            # Update sessionID timestamp for the user to the current time
            session_data["timestamp"] = datetime.datetime.now().timestamp()
            # Extract username and target information-------------------------------------------------CHECK
            target = request_headers.get("target")
            # Check if the file exists
            file_path = f"{root_directory}/{username}/{target}"
            try: #this is IF
                with open(file_path, "r") as file:
                    file_content = file.read()
                # Log with MESSAGE "GET SUCCEEDED: {username} : {target}"
                print(f"GET SUCCEEDED: {username} : {target}")
                # Return HTTP status "200 OK" with body containing the contents of the file
                return "200 OK", file_content
            except FileNotFoundError:
                # Log with MESSAGE "GET FAILED: {username} : {target}"
                print(f"GET FAILED: {username} : {target}")
                # Return HTTP status "404 NOT FOUND"
                return "404 NOT FOUND"
        else:
            # Log with MESSAGE "SESSION EXPIRED: {username} : {target}"
            print(f"SESSION EXPIRED: {username} : {target}")
            # Return HTTP status "401 Unauthorized"
            return "401 Unauthorized"
    else:
        # Log with MESSAGE "COOKIE INVALID: {target}"
        print(f"COOKIE INVALID: {request_headers.get('target')}")
        # Return HTTP status "401 Unauthorized"
        return "401 Unauthorized"
    
# Function to start the server
def start_server(ip, port, accounts_file, session_timeout, root_directory):
    global SESSION_TIMEOUT
    SESSION_TIMEOUT = int(session_timeout)
    # Load existing sessions from a file if available---------------------------------------------SHOULD THIS BE DONE EARLIER?
    try:
        with open("sessions.json", "r") as f:
            global sessions
            sessions = json.load(f)
    except (IOError, json.JSONDecodeError):
        sessions = {}
    # Create and bind a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, int(port)))
    # Start listening for incoming connections
    server_socket.listen(1)
    ####################print(f"Server is running on {ip}:{port}")
    while True:
        # Accept an incoming connection
        client_socket, client_address = server_socket.accept()
        # Receive an HTTP request from the client
        request = client_socket.recv(1024).decode("utf-8")
        # Extract the HTTP method, request target, and HTTP version
        method, target, _ = request.split("\r\n")[0].split(" ")
        # If HTTP method is "POST" and request target is "/":
        if method == "POST" and target == "/":
            # Handle POST request and send response
            response_status, response_body = handle_login(parse_headers(request))
        # Elif HTTP method is "GET":
        elif method == "GET":
            # Handle GET request and send response
            response_status, response_body = handle_file_download(parse_headers(request), root_directory)
        else:
            # Else: Send HTTP status 501 Not Implemented
            response_status = "501 Not Implemented"
            response_body = ""
        # Close the connection
        response = f"HTTP/1.1 {response_status}\r\n\r\n{response_body}"
        client_socket.sendall(response.encode())
        client_socket.close()
        
################ BELOW FUNCTIONS ARE TO SIMPLIFY THE CODE #################
        
# Function to validate user credentials
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

#function to generate session ID
def create_session(session_id, username):
    session_data = {"username": username, "timestamp": datetime.datetime.now().timestamp()}
    sessions[session_id] = session_data
    
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

################ ABOVE FUNCTIONS ARE TO SIMPLIFY THE CODE #################

# Function Main
if __name__ == "__main__":
    start_server(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    save_sessions()