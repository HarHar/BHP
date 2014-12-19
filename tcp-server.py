"""
Create a standard multi-threaded TCP server
"""

import socket
import threading

# First pass in the IP address and port we want server to listen on
bind_ip = "0.0.0.0"
bind_port = 9999
# setup TCP socket stream
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# bind to IP and port
server.bind((bind_ip,bind_port))
# Start listening with max backlog of connections of 5
server.listen(5)

print "[*] Listening on %s:%d" % (bind_ip,bind_port)

# this is our client-handling thread
def handle_client(client_socket):

    # print out what the client sends
    request = client_socket.recv(1024)

    print "[*] Received: %s" % request

    # send back a packet
    client_socket.send("ACK!")

    client_socket.close()


while True:
# When a client connects, receive client socket into the client variable
# Receive remote connection details into the addr variable
    client,addr = server.accept()

    print "[*] Accepted connection from %s:%d" % (addr[0],addr[1])

# point to our handle_client function and pass it the client socket object as argument
# spin up our client thread to handle incoming data
    client_handler = threading.Thread(target=handle_client,args=(client,))
    client_handler.start()   # Main server ready to handle another incoming connection
