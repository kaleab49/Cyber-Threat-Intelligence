import socket

def reverse_dns(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return {"hostname": hostname}
    except Exception:
        return {}