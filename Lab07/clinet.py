import socket

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # 1. Connect to the server using the HOST and PORT variables
    s.connect((HOST, PORT))

    # 2. Create a string variable named 'message' containing your Student ID and the word "robux"
    message = "801349070 robux"

    # 3. Encode the message string to bytes and send it to the server
    s.sendall(message.encode())

    # 4. Receive the server's response (buffer size 1024) and assign it to a variable called 'reply'
    reply = s.recv(1024)

    # 5. Decode and print the 'reply' variable to your terminal
    print(reply.decode())