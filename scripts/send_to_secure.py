import os
import sys
import time
import re

secure_ip = "10.0.0.10"
secure_port = "20000"

class Tail(object):
    def __init__(self, tailed_file):
        self.check_file_validity(tailed_file)
        self.tailed_file = tailed_file
        self.callback = sys.stdout.write
 
    def follow(self, s=1):
        with open(self.tailed_file) as file_:
            # Go to the end of file
            file_.seek(0,2)
            while True:
                curr_position = file_.tell()
                line = file_.readline()
                if not line:
                    file_.seek(curr_position)
                else:
                    self.callback(line)
                time.sleep(s)
 
    def register_callback(self, func):
        self.callback = func
 
    def check_file_validity(self, file_):
        if not os.access(file_, os.F_OK):
            raise TailError("File '%s' does not exist" % (file_))
        if not os.access(file_, os.R_OK):
            raise TailError("File '%s' not readable" % (file_))
        if os.path.isdir(file_):
            raise TailError("File '%s' is a directory" % (file_))
 
class TailError(Exception):
    def __init__(self, msg):
        self.message = msg
    def __str__(self):
        return self.message

def send_to_secure(txt):
    buf = open("sts_buf","w")
    match = re.compile("\[Classification: (.*?)\]").findall(txt)
    buf.write(match[0] + '\n')
    match = re.compile("\[Priority: (.*?)\]").findall(txt)
    buf.write(match[0] + '\n')
    match = re.compile("} (.*?):").findall(txt)
    buf.write(match[0] + '\n')
    match = re.compile("> (.*?):",re.S).findall(txt)
    buf.write(match[0] + '\n')
    match = re.compile("(.+)  \[\*",re.S).findall(txt)
    buf.write(match[0] + '@')
    buf.close()
    os.popen("cat sts_buf | nc {0} {1} &".format(secure_ip, secure_port))
    os.popen("pkill nc")
    os.popen("rm sts_buf")
        
t = Tail(sys.argv[1])

t.register_callback(send_to_secure)
 
t.follow(s=0.05)
