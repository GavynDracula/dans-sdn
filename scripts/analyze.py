#! /usr/bin/python2
# coding=utf-8

import sys
import json
import sqlite3

pkglist = []
pkg_vul = {}
#pkg_ver = ""
entry_list = []
instruct = ""
cve = ""
sig_list = ["-","ubuntu","fedro","opensusu","debian","mandriva","mint","gentoo","centos"]


pkginfo = json.load(open("{0}".format(sys.argv[1]),'r'))

def pkg_modify(pkgver):
    pkg_tab = []
    pkg_tab = pkgver
    for sig in sig_list:
        if sig in pkg_tab:
            num = pkg_tab.index(sig)
            pkg_tab =  pkg_tab[:num]
    if pkg_tab[-1] == '.':
        pkg_tab = pkg_tab[:-1]
    return ''.join(pkg_tab)
    
for pkg in pkginfo:
    pkg["Version"] = pkg_modify(pkg["Version"])
    pkglist.append(pkg["Pkg"] +':' + pkg["Version"])

conn = sqlite3.connect("{0}".format(sys.argv[2]))
curs = conn.cursor()

for pkg in pkglist:
    instruct = "select entry_id from products where value like '%{0}%'".format(pkg)
    curs.execute(instruct)
    entry_list = curs.fetchall()
    if len(entry_list) > 0:
        pkg_vul[pkg] = []
        for entry in entry_list:
            instruct = "select c_v_e_id from entries where id = {0}".format(entry[0])
            curs.execute(instruct)
            cve = curs.fetchall()[0][0]
            pkg_vul[pkg].append(cve)

curs.close()
conn.close()

json.dump(pkg_vul,open('testresult','w'))
