#!/usr/bin/env python
# coding=utf-8

import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('', 8000))
sock.listen(5)
while True:
    connection,address = sock.accept()
    print connection.recv(1024)
    connection.close()

