import hashlib
import getpass
import socket

#Server connection settings
#127.0.0.1 is a loopback adress that points to this machine
#8080 is the port number that this server will use as it is default for a http server
HOST = "127.0.0.1"
PORT = 8080

#Main Client Function
def main():

    #Ask the user for credentials to initialise the request
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")

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
            print(response_text)

if __name__ == "__main__":
    main()
        


    

