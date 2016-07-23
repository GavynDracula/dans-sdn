#!/usr/bin/env python2
# coding=utf-8

import os

snortactions = ["alert", "log", "pass", "activate", "dynamic"]
rulelist = []
cve2rules = {}

rulespath = "/home/dracula/dans/snort-new/rules/"
#rulespath = "/home/dracula/download/snort/rules/ignore/"
ruleslist = os.listdir(rulespath)

for rules in ruleslist:
    if ".rules" not in rules:
        ruleslist.remove(rules)
        continue
    file = open(rulespath + rules,'r')
    lines = file.readlines()
    for line in lines:
        if line[0] == '#' and len(line) != 0 and len(line.split()) > 1 and line.split()[1] in snortactions:
            rule = line.split()
            rule.pop(0)
            rulelist.append(' '.join(rule)+'\n')
#        if line[0] != '#' and len(line) != 0 and len(line.split()) > 1 :
#            rulelist.append(line)


file = open("rules",'w+')
for rule in rulelist:
    file.write(rule)

#for rule in rulelist:
#    elements =  ' '.join(rule.split()[7:])[1:-2].split(';')
#    for element in elements:
#        if "cve" in element:
#            cveid = "CVE-" + element[element.index("cve") + 4:element.index("cve") + 13]
#            if not cve2rules.has_key(cveid):
#                cve2rules[cveid] = []
#            cve2rules[cveid].append(rule)

