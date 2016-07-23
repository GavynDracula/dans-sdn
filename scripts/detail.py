#!/usr/bin/env python
# coding=utf-8

import os
import sys 
import json
import sqlite3 

json_list = os.listdir(sys.argv[1])
cve_db = "/home/dracula/dans/database/cve.db"

conn = sqlite3.connect("{0}".format(cve_db))
curs = conn.cursor()

for  json_f in json_list:
    if os.path.isdir(os.path.join(sys.argv[1], json_f)):
        continue
    pkg_cve = json.load(open(os.getcwd()+'/'+sys.argv[1]+json_f,'r'))
    pkg_list = pkg_cve.keys()
    for pkg in pkg_list:
        cve_list = pkg_cve[pkg]
        cve_detail_list = {}
        for cve in cve_list:
            cve_detail = {}
            instruct = "select id from entries where c_v_e_id='{0}'".format(cve)
            curs.execute(instruct)
            entry_id = curs.fetchall()[0][0]
            instruct = "select * from c_v_s_s where entry_id={0}".format(entry_id)
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
            cve_detail_list[cve] = cve_detail
        pkg_cve[pkg] = cve_detail_list
    json.dump(pkg_cve,open(sys.argv[1]  + "details/" + json_f + '.detail','w'))
    

curs.close()
conn.close()
