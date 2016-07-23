#!/usr/bin/env python
# coding=utf-8

import sqlite3

MAX=20
num = 1
i = 1

dbpath = "../database/cve-new.db"
conn = sqlite3.connect(dbpath)
curs = conn.cursor()
curs.execute("select * from rules where c_v_e_id='NULL' and default_load='YES'")
result = curs.fetchall()
print len(result)
file = open("default_load.rules",'w')
for each in result:
    rule = each[2].replace("'",'''"''')
    file.write(rule)
file.close()
'''
file = open("default_not_%d.rules"%num,'w')
for each in result:
    if i < MAX:
        file.write(each[2])
        i += 1
    else:
        file.write(each[2])
        file.close()
        num += 1
        file = open("default_not_%d.rules"%num,'w')
        i = 1
file.close()
'''
