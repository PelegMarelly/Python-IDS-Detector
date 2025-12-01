import socket

target_ip = "10.0.0.63" # change to your own IP

for port in range(20, 50):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        sock.connect((target_ip, port))
        sock.close()
    except:
        pass
