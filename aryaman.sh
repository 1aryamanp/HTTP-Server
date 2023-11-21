# Set your server IP and port
SERVER_IP="127.0.0.1"
SERVER_PORT="8080"

# Variables for storing session cookies
SESSION_COOKIE1=""
SESSION_COOKIE2=""

# Common curl options for HTTP/1.0 and connection close
CURL_OPTIONS="--http1.0 --connect-timeout 5 --max-time 10 --fail --silent"

# Test Case 1: No Username (POST at the root)
echo "test1"
curl $CURL_OPTIONS -v -X POST "http://${SERVER_IP}:${SERVER_PORT}/"

# Test Case 2: No Password (POST at the root)
echo "test2"
curl $CURL_OPTIONS -v -X POST -H "username: Richard" "http://${SERVER_IP}:${SERVER_PORT}/"

# Test Case 3: Username incorrect (POST at the root)
echo "test3"
curl $CURL_OPTIONS -v -X POST -H "username: IncorrectUser" -H "password: 3TQI8TB39DFIMI6" "http://${SERVER_IP}:${SERVER_PORT}/"

# Test Case 4: Password incorrect (POST at the root)
echo "test4"
curl $CURL_OPTIONS -v -X POST -H "username: Richard" -H "password: IncorrectPassword" "http://${SERVER_IP}:${SERVER_PORT}/"

# Test Case 5: Username correct/password correct (POST at the root)
echo "test5"
SESSION_COOKIE1=$(curl -i -v -X POST -H "username: Richard" -H "password: 3TQI8TB39DFIMI6" "http://${SERVER_IP}:${SERVER_PORT}/" | grep -i 'Set-Cookie' | cut -d ' ' -f 2 | cut -d '=' -f 2)
echo "\\nCookie (sessionID) for user 1: $SESSION_COOKIE1"

# Test Case 6: Username (1st username) correct/password correct (POST at the root) -> Generate a new cookie (POST at the root)
echo "test6"
SESSION_COOKIE1=$(curl -i -v -X POST -H "username: Richard" -H "password: 3TQI8TB39DFIMI6" "http://${SERVER_IP}:${SERVER_PORT}/" | grep -i 'Set-Cookie' | cut -d ' ' -f 2 | cut -d '=' -f 2)
echo "\\nNew Cookie (sessionID) for user 1: $SESSION_COOKIE1"

# Test Case 7: Invalid cookie (GET)
echo "test7"
curl $CURL_OPTIONS -v -X GET -H "Cookie: sessionID=InvalidCookie" "http://${SERVER_IP}:${SERVER_PORT}/file.txt"

# Test Case 8: Username correct (1st username)(GET filename for user 1) correct
echo "test8"
curl $CURL_OPTIONS -v -X GET -H "Cookie: sessionID=$SESSION_COOKIE1" "http://${SERVER_IP}:${SERVER_PORT}/file_user1.txt"

# Test Case 9: Username (2nd username) correct/password correct (POST)
echo "test9"
SESSION_COOKIE2=$(curl -i -v -X POST -H "username: AnotherUser" -H "password: AnotherPassword" "http://${SERVER_IP}:${SERVER_PORT}/" | grep -i 'Set-Cookie' | cut -d ' ' -f 2 | cut -d '=' -f 2)
echo "\\nCookie (sessionID) for user 2: $SESSION_COOKIE2"

# Test Case 10: GET file successful (GET filename for user 2)
echo "test10"
curl $CURL_OPTIONS -v -X GET -H "Cookie: sessionID=$SESSION_COOKIE2" "http://${SERVER_IP}:${SERVER_PORT}/file_user2.txt"

# Test Case 11: GET file not found (GET FAIL)
echo "test11"

# Sleep for 6 seconds
echo "test sleep"
sleep 6

# Test Case 12: Expired cookie with username 2 (GET filename for user 2)----------------ok
echo "test12"
curl $CURL_OPTIONS -v -X GET -H "Cookie: sessionID=$SESSION_COOKIE2" "http://${SERVER_IP}:${SERVER_PORT}/file_user2.txt"
