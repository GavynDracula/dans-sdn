#!/usr/bin/env python
# coding=utf-8

import sqlite3

dbpath = "../../database/cve-new.db"
conn = sqlite3.connect(dbpath)
curs = conn.cursor()
curs.execute("select c_v_e_id from rules where c_v_e_id!='NULL' and default_load='YES'")
cvelist = curs.fetchall()
for cve in cvelist:
    instruct = "select * from rules where c_v_e_id='{0}' and default_load='YES'".format(cve[0])
    curs.execute(instruct)
    result = curs.fetchall()
    file = open("{0}.rules".format(cve[0]),'w')
    for each in result:
        rule = each[2].replace("'",'''"''')
        file.write(rule)
    file.close()
