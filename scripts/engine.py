#!/usr/bin/env python2
# coding=utf-8

import json
import docker

containers = docker.Client().containers()
images = docker.Client().images()
name2ip = {"httpserver":"10.0.0.1","backserver":"10.0.0.2","switch":"10.0.0.10","snort":"10.0.0.11","extern":"10.0.0.101"}
containerlist = []
info_path = "/home/dracula/dans/result/dans/details/"
policy_file = "./policy"

def image2id(name):
    for image in images:
        if name in image["RepoTags"]:
            return image["Id"]

class Image:
    def __init__(self, imageid, name, id, ip):
        self.imageid = imageid
        self.name = name
        self.id = id
        self.ip = ip
        self.info = {}
        self.funclist = []
        self.cvelist = {}

    def set_info(self,image_file):
        self.info = json.load(open(image_file,'r'))
    
    def set_cvelist(self):
        for pkg_info in self.info.values():
            for cve in pkg_info:
                self.cvelist[cve] = pkg_info[cve]

    def set_funclist(self,policy_file):
        file = open(policy_file,'r')
        policy = file.readlines()
        funclist = []
        for cve in self.cvelist:
            alert = 0
            score = self.cvelist[cve]["score"]
            access_vector = self.cvelist[cve]["access_vector"]
            access_complexity = self.cvelist[cve]["access_complexity"]
            authentication = self.cvelist[cve]["authentication"]
            confidentiality_impact = self.cvelist[cve]["confidentiality_impact"]
            integrity_impact = self.cvelist[cve]["integrity_impact"]
            availability_impact = self.cvelist[cve]["availability_impact"]
            for cmd in policy:
                if "alert==0" not in cmd and "alert == 0" not in cmd:
                    continue
                cmd = cmd.replace('&&', ' and ')
                cmd = cmd.replace('||', ' or ')
                cmd = cmd.replace('!', ' not ')
                cmd = cmd.replace('IF', 'if')
                cmd = cmd.replace('  ',' ')
                cmd = cmd.replace(' THEN ', ':\n')
                cmd = cmd.replace('[', "    funclist.append('")
                cmd = cmd.replace(',', "')\n    funclist.append('")
                cmd = cmd.replace(']', "')")
                cmd = cmd[:-1]
                exec cmd
        self.funclist = sorted(set(funclist),key=funclist.index)

def set_containerlist():
    for container in containers:
        name = container["Names"][0][1:]
        if name not in name2ip.keys():
            continue
        instance = Image(image2id(container["Image"]),name,container["Id"],name2ip[name])
        instance.set_info(info_path + instance.imageid[:12] + "-pkgdata.result.detail")
        instance.set_cvelist()
        instance.set_funclist(policy_file)
        containerlist.append(instance)

if __name__ == "__main__":
    set_containerlist()
    for each in containerlist:
        print each.funclist
