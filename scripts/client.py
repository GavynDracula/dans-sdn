#!/usr/bin/env python
# coding=utf-8
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("10.0.0.11",8000))
sock.send("test")
sock.close()
