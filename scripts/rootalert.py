#!/usr/bin/env python
# coding=utf-8

import os
import re
import time

secure_ip = "10.0.0.10"
secure_port = "20000"
tm = ""

def ps_read():
    global tm
    os.popen("ps -fa > tmp_buf")
    buf = open("tmp_buf","r")
    result = re.compile("root .*? su\\n").findall(buf.read())
    buf.close()
    os.popen("rm tmp_buf")
    if (len(result)!= 0 and tm != result[0].split()[4]):
        tm = result[0].split()[4]
        buf = open("send_buf","w")
        buf.write("Root Warning" + '\n' + "4" + '\n' + "10.0.0.1" + '\n' + "10.0.0.1" + '\n' + tm + '@')
        buf.close()
        os.popen("cat send_buf | nc {0} {1} &".format(secure_ip, secure_port))
        os.popen("pkill nc")
        os.popen("rm send_buf")

while True:
    ps_read()
    time.sleep(0.5)
