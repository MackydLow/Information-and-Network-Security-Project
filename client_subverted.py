#Imports
import hashlib
import getpass
import re
import socket

#Set host and port for the server we want to connect to.
HOST = "127.0.0.1"
PORT = 8080

#Suffix to append to the username.
SERVICE_SUFFIX = "@internal"
SERVICE_KEY = "py_http_internal"

#A function here for encoding to SHA-256, returned as a hex string.
def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

#Send request function with two optional parameters.
def send_request(auth_header=None, service_token=None):
    request = (
        "GET / HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
    )

    #If there is an auth header parameter, add it to the request.
    if auth_header:
        request += f"Authorization: {auth_header}\r\n"

    #If there is a service token parameter, add it to the request.
    if service_token is not None:
        request += f"X-Forwarded-Host: {service_token}\r\n"

    request += "Connection: close\r\n\r\n"

    #Establish a TCP connection to the server.
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        
        #Encodes the request and sends it to the server.
        sock.sendall(request.encode("utf-8"))

        #Receives the response from the server. Breaks it into chunks.
        response = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)

        #the decoded response is returned as a string.
        return response.decode("utf-8", errors="ignore")

#Main Client Function
def main():

    #Ask the user for a username.
    base_username = input("Base username:")

    #If the username is empty, print an error message.
    if not base_username:
        print("Username cannot be empty.")
        return

    #Now the name is combined with the suffix.
    username = base_username + SERVICE_SUFFIX  

    #Send the initial request to the server without any authentication headers to get the Digest challenge.
    initial_response = send_request()

    #If the initial response is None, print an error message.
    if initial_response is None:
        print("No response from server.")
        return

    else:
        status_line = initial_response.splitlines()[0]

    #Search the response for the Digest challenge.
    challenge = re.search(
        r'WWW-Authenticate:\s*Digest\s+([^\r\n]+)',
        initial_response,
        re.IGNORECASE
    )

    #If no challenge is found, print an error message.
    if not challenge:
        print("No challenge found in the response.")
        return

    #This variable stores the challenge data from the server's response.
    challenge_data = challenge.group(1)

    #Find the realm and nonce values from the challenge data using regular expressions.
    realm_match = re.search(r'realm="([^"]+)"', challenge_data)
    nonce_match = re.search(r'nonce="([^"]+)"', challenge_data)

    #If either the realm or nonce values are not found, print an error message.
    if not realm_match or not nonce_match:
        print("No realm or nonce match found from challenge.")
        return

    #Variables to store the realm and nonce values extracted from the challenge data.
    realm = realm_match.group(1)
    nonce = nonce_match.group(1)

    #Calculate the client nonce and the response hash using the base username, nonce, and service key.
    #The first 16 characters of the SHA-256 hash of the nonce and service key are used as the client nonce.
    cnonce = sha256(f"{nonce}:{SERVICE_KEY}")[:16]
    response_hash = sha256(f"{base_username}:{nonce}:{SERVICE_KEY}")

    #Prompt the user for the internal service token.
    service_token = getpass.getpass("Internal service token: ")

    #Now we can create the Authorization header for the Digest Authentication request.
    auth_header = (
        f'Digest username="{username}", '
        f'realm="{realm}", '
        f'nonce="{nonce}", '
        f'uri="/", '
        f'response="{response_hash}", '
        f'qop=auth, '
        f'nc=00000001, '
        f'cnonce="{cnonce}", '
        f'algorithm=SHA-256'
    )

    #Send the authenticated request with the Authorization header and service token.
    response = send_request(auth_header, service_token)
    
    #Display the authenticated response from the server.
    print("\nAuthenticated response:")
    
    if response:
        status_line = response.splitlines()[0]
        print(status_line)

    else:
        print("No response from server.")
    
if __name__ == "__main__":
    main()