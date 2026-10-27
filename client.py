import hashlib
import getpass
import socket
import re
import secrets

#Server connection settings
#127.0.0.1 is a loopback adress that points to this machine
#8080 is the port number that this server will use as it is default for a http server
HOST = "127.0.0.1"
PORT = 8080

def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def send_request(auth_header=None):
    request = (
          "GET / HTTP/1.1\r\n"
          f"Host: {HOST}:{PORT}\r\n"
     )

    if auth_header:
        request += f"Authorization: {auth_header}\r\n"

    request += "Connection: close\r\n\r\n"

    with socket.create_connection((HOST, PORT), timeout=10) as client_socket:
        client_socket.sendall(request.encode("utf-8"))

        response = bytearray()
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            response.extend(chunk)

        return response.decode("utf-8", errors="replace")


#Main Client Function
def main():

    #Ask the user for credentials to initialise the request
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")

    challenge_response = send_request()

    print("Initial response:", challenge_response.splitlines()[0])

    challenge = re.search(r'WWW-Authenticate:\s*Digest\s+([^\r\n]+)',
                          challenge_response, 
                          re.IGNORECASE)
    if not challenge:
        print(" No Digest challenge recieved from the server.")
        print(challenge_response)
        return

    challenge_data = challenge.group(1)

    realm_match = re.search(r'realm="([^"]+)"', challenge_data)
    nonce_match = re.search(r'nonce="([^"]+)"', challenge_data)

    if not realm_match or not nonce_match:
        print("Could not read the Digest challenge.")
        return

    realm = realm_match.group(1)
    nonce = nonce_match.group(1)

    uri = "/"
    method = "GET"
    qop = "auth"
    nc = "00000001"
    cnonce = secrets.token_hex(16)

    stored_hash = sha256(password)
    ha1 = sha256(f"{username}:{realm}:{stored_hash}")
    ha2 = sha256(f"{method}:{uri}")

    response_hash = sha256(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")

    auth_header = (
        f'Digest username="{username}", '
        f'realm="{realm}", '
        f'nonce="{nonce}", '
        f'uri="{uri}", '
        f'response="{response_hash}", '
        f'qop={qop}, '
        f'nc={nc}, '
        f'cnonce="{cnonce}", '
        f'algorithm=SHA-256'
    )

    # Send the authenticated request
    authenticated_response = send_request(auth_header)

    # Print the status and full response
    print("\nAuthenticated response:")
    print(authenticated_response)

    # Send the second request with the Digest Authentication header
    authenticated_response = send_request(auth_header)

    # Display the server's response
    print("\nAuthenticated response:")
    print(authenticated_response.splitlines()[0])

    # Display the complete response for debugging
    print(authenticated_response)

    """
    #Hash the password using SHA-256 from the standard library
    #This is encoded as a hexidecimal string to be sent over the network
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    #Now the request is built as a string
    #It uses \r and \n to separate the lines as per the HTTP protocol
    request = (
        #This line specifies the method (GET) and the type of request (HTTP/1.1)
        "GET / HTTP/1.1\r\n"
        
        #This line includes the HOST and PORT variables created earlier so the location of the request is known to the server
        f"Host: {HOST}:{PORT}\r\n"

        #This line includes the username and hashed password in the request headers
        f"Authorization: Digest username='{username}', response='{hashed_password}'\r\n"

        #The connection is closed after the request is sent
        "Connection: close\r\n"
        "\r\n"
        )

    #Try/Catch block handles exceptions for this part (implememt later)
    #try:

        #Open a TCP socket and connect to the server
    with socket.create_connection((HOST, PORT), timeout=10) as client_socket:
            #Send the HTTP request to the server
            client_socket.sendall(request.encode("utf-8"))

            #Receive the response from the server
            response = bytearray()
            while True:
                #Receive data in chunks
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)

            #Decode the response ready for display
            response_text = response.decode("utf-8", errors="replace")

            #Print the response to the console

            #HTTP status line and code:
            status_line = response_text.splitlines()[0]
            print ("Server response:")
            print(status_line)
            print("\n")

            #Print the rest of the response body (if any)
            print("Response body:")
            print(response_text)"""

if __name__ == "__main__":
    main()

        


    

