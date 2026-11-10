import socket
import sys
import time

# Listen on the given TCP port on all addresses until the container ends.
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen()
time.sleep(3600)
