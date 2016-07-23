#!/usr/bin/env python2
# coding=utf-8

import os
import sys
import time
import re
import json
import sqlite3


end_flag = 0

class Tail(object):
    def __init__(self, tailed_file):
        self.check_file_validity(tailed_file)
        self.tailed_file = tailed_file
        self.callback = sys.stdout.write
 
    def follow(self, s=1):
        global end_flag
        with open(self.tailed_file) as file_:
            file_.seek(0,2)
            while True:
                curr_position = file_.tell()
                line = file_.readline()
                if end_flag != 2:
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


class collector:
    def __init__(self,db_path,out_path,repo):
        self.cve_db = db_path
        self.out_path = out_path
        self.log_path = "/root/.banyan/hostcollector/collector.log"
        self.pkg_path = "/root/.banyan/hostcollector/banyanout/pkgextractscript/"
        self.file_list = []
        self.pkg_match_str = "Writing \/root\/.banyan\/hostcollector\/banyanout\/pkgextractscript\/(.*?)\.\.\."
        self.loop_match_str = "(.*?)Looping in 60 seconds"
        self.nonew_match_str = "(.*?)No new metadata in this iteration"
        self.siglist = ["-","ubuntu","fedro","opensuse","debian","mandriva","mint","gentoo","centos","squeeze"]
        self.repo = repo
       
    def pkg_modify(self,pkgver):
        pkg_tab = []
        pkg_tab = pkgver
        for sig in self.siglist:
            if sig in pkg_tab:
                num = pkg_tab.index(sig)
                pkg_tab =  pkg_tab[:num]
        if pkg_tab[-1] == '.':
            pkg_tab = pkg_tab[:-1]
        return ''.join(pkg_tab)

    def pkg_analyse(self):
        pkglist = []
        pkg_vul = {}
        entry_list = []
        instruct = ""
        cve = ""
        for pkg_file in self.file_list:
            name = pkg_file
            pkg_file = self.pkg_path + pkg_file + ".json"
            pkginfo = json.load(open("{0}".format(pkg_file),'r'))
            for pkg in pkginfo:
                #pkg["Pkg"] = self.pkg_modify(pkg["Pkg"])
                pkg["Version"] = self.pkg_modify(pkg["Version"])
                pkglist.append(pkg["Pkg"] +':' + pkg["Version"])
            conn = sqlite3.connect("{0}".format(self.cve_db))
            curs = conn.cursor()
            for pkg in pkglist:
                instruct = "select entry_id from products where value like '%{0}%'".format(pkg)
                curs.execute(instruct)
                entry_list = curs.fetchall()
                if len(entry_list) > 0:
                    pkg_vul[pkg] = {}
                    for entry in entry_list:
                        cve_detail = {}
                        instruct = "select c_v_e_id from entries where id = {0}".format(entry[0])
                        curs.execute(instruct)
                        cve = curs.fetchall()[0][0]
                        instruct = "select * from c_v_s_s where entry_id={0}".format(entry[0])
                        curs.execute(instruct)
                        details = curs.fetchall()[0]
                        cve_detail["score"] = details[2]
                        cve_detail["access_vector"] = details[3]
                        cve_detail["access_complexity"] = details[4]
                        cve_detail["authentication"] = details[5]
                        cve_detail["confidentiality_impact"] = details[6]
                        cve_detail["integrity_impact"] = details[7]
                        cve_detail["availability_impact"] = details[8]
                        #cve_detail["source"] = details[9]
                        #cve_detail["generated_on_date"] = details[10]
                        pkg_vul[pkg][cve] = cve_detail
            curs.close()
            conn.close()
            json.dump(pkg_vul,open(self.out_path + name + '.result','w'))
        sys.exit()    

    def deal(self,log):
        global end_flag
        match = re.compile(self.pkg_match_str).findall(log)
        if len(match) > 0:
            self.file_list.append(match[0])
        match = re.compile(self.loop_match_str).findall(log)
        if len(match) > 0:
            end_flag = 1
        match = re.compile(self.nonew_match_str).findall(log)
        if len(match) > 0:
            if end_flag == 1:
                os.popen("pkill collector")
                end_flag = 2
                if len(self.file_list) > 0:
                    self.pkg_analyse()
                else :
                    sys.exit()
            else:
                end_flag = 0

    def collect(self):
        readlog = Tail(self.log_path)
        readlog.register_callback(self.deal)
        readlog.follow(s=0.05)

col = collector("/home/dracula/dans/database/cve.db","/home/dracula/dans/result/","dracula36/dans")
col.collect()
