#!/usr/bin/env python2
# coding=utf-8

import sys

dangerous_sig = "Dangerous"
def output(str):
    print str

file_path = sys.argv[1]
file = open(file_path, 'r')
policy = file.readlines()
score = 6.0
for each in policy:
    each = each.replace('&&', ' and ')
    each = each.replace('||', ' or ')
    each = each.replace('!', ' not ')
    each = each.replace('IF', 'if')
    each = each.replace('  ',' ')
    each = each.replace(' THEN ', ':\n')
    each = each.replace('[', '    ')
    each = each.replace(',', '\n    ')
    each = each.replace(']', '')
    each = each[:-1]
    print each

