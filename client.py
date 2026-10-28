#imports
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

#A function here for encoding to SHA-256, returned as a hex string
def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

#The function for sending requests to the server.
def send_request(auth_header=None):
    request = (
          "GET / HTTP/1.1\r\n"
          f"Host: {HOST}:{PORT}\r\n"
     )

    #If there is an auth header parameter, add it to the request.
    if auth_header:
        request += f"Authorization: {auth_header}\r\n"

    request += "Connection: close\r\n\r\n"

    #Establish a TCP connection to the server.
    with socket.create_connection((HOST, PORT), timeout=10) as client_socket:
        
        #Encodes the request and sends it to the server.
        client_socket.sendall(request.encode("utf-8"))

        #Receives the response from the server. Breaks it into chunks.
        response = bytearray()
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            response.extend(chunk)

        #the decoded response is returned as a string.
        return response.decode("utf-8", errors="replace")


#Main Client Function
def main():

    #Ask the user for credentials to initialise the request
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")

    #A request is sent without and authentication header to get the Digest challenge from the server.
    #This has been tested in previous versions and returns a 401 error as intended.
    challenge_response = send_request()

    #Search the response for the Digest challenge.
    challenge = re.search(r'WWW-Authenticate:\s*Digest\s+([^\r\n]+)',
                          challenge_response, 
                          re.IGNORECASE)

    #If no challenge is found, print an error message.
    if not challenge:
        print(" No Digest challenge recieved from the server.")
        print(challenge_response)
        return
    
    #This variable stores the challenge data from the server's response.
    challenge_data = challenge.group(1)

    #Find the realm and nonce values from the challenge data using regular expressions.
    realm_match = re.search(r'realm="([^"]+)"', challenge_data)
    nonce_match = re.search(r'nonce="([^"]+)"', challenge_data)

    #If either the realm or nonce values are not found, print an error message.
    if not realm_match or not nonce_match:
        print("Could not read the Digest challenge.")
        return

    #Variables to store the realm and nonce values extracted from the challenge data.
    realm = realm_match.group(1)
    nonce = nonce_match.group(1)

    #Set key values, and generate a client nonce.
    uri = "/"
    method = "GET"
    qop = "auth"
    nc = "00000001"
    cnonce = secrets.token_hex(16)

    #Hash the password and generate the HA1 and HA2 values for the Digest Authentication response.
    stored_hash = sha256(password)
    ha1 = sha256(f"{username}:{realm}:{stored_hash}")
    ha2 = sha256(f"{method}:{uri}")

    #Calculate the hash for the final response using all the data we have gathered so far.
    response_hash = sha256(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")

    #Now we can create the Authorization header for the Digest Authentication request.
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
    
    # Send the second request with the Digest Authentication header
    authenticated_response = send_request(auth_header)

    # Display the server's response
    print("\nAuthenticated response:")
    print(authenticated_response.splitlines()[0])

if __name__ == "__main__":
    main()

        


    

