# coding=utf-8

from pox.core import core     #pox核心库
from pox.lib.revent import revent     #pox事件处理库
import pox.openflow.libopenflow_01 as of     #pox的openflow库
from pox.lib.addresses import IPAddr     #pox自带地址转换
from pox.lib.addresses import EthAddr     #pox自带地址转换
import pox.openflow.spanning_tree     #pox网络拓扑结构库
import pox.openflow.discovery
import asyncore     #异步socket包装库
import mysql.connector     #python对mysql数据库的支持
# 该库用于对python基本类型值与用C struct类型之间的转化
import struct
import asynchat     #异步socket命令/相应器
import socket     #socket通信库
import thread     #python对多线
import threading  #的程处理
import os     #该库包括与系统相关的函数
import sys  
import re
import json
import sqlite3
import docker
import time     #python的时间库
import pyinotify     #监视文件系统事件库
import random     #随机库

log = core.getLogger()     #pox的日志系统
snortlist = {}     #{SNORT_DPID:(ip(/mask),EthAddr(mac))}
# 下面这两个字典实现了服务名与对应IP的转换
ip2serv_name = {"10.0.0.1" : "http", "10.0.0.2" : "http"}
serv_name2ip = {"http" : ["10.0.0.1", "10.0.0.2"]}
containerlist = []
switchlist = {}
cvelist = []
end_flag = 0
MAXCMD = 100     #读取命令的最大字节数
DEFAULT_MASK = "/24"
# 下面五个变量声明了五个安全级别
HIGHER = 5
HIGH = 4
MID = 3
LOWMID = 2
LOW = 1
logfile = "/home/dans/pox/dans/log/danslog"

def logwrite(log):
    file = open(logfile,'a')
    file.write(log)
    file.close()

def find_shortest_route(graph, start, end, path=[]):
    """
    根据graph字典提供的信息计算从start到end的最短路径
    graph的数据结构类似于：
    {s1:([(s2,port1),(s3,port2),...]),s2:([(s1,port),...]),...}
    """
    path = path + [start]
    if start == end:
        return path
    if not graph. has_key(start):
        return None
    shortest = []
    #分析部分，注意用到了递归调用
    start_list = graph[start]
    for item in start_list:
        if item[0] not in path:
            newpath = find_shortest_route(graph, item[0], end, path)
            if newpath:
                if not shortest or len(newpath) < len(shortest):
                    shortest = newpath
    return shortest

def get_shortest_route(graph, start, end):
    """
    根据find_shortest_route的返回值，找到最短路径
    """
    path = []
    route = find_shortest_route(graph, start, end)
    #添加从一个节点到另一个节点的端口信息
    for index in range(0, len(route)-1):
        for item in graph[route[index]]:
            if item[0] == route[index+1]:
                path = path + [(route[index], item[1])]
                break
    path += [route[-1]]
    return path

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
                else :
                    return
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
        conn = sqlite3.connect("{0}".format(self.cve_db))
        for pkg_file in self.file_list:
            name = pkg_file
            log.info("collector:Analysing data from %s"%name)
            logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "collector:Analysing data from %s"%name + '\n')
            pkg_file = self.pkg_path + pkg_file + ".json"
            pkginfo = json.load(open("{0}".format(pkg_file),'r'))
            for pkg in pkginfo:
                #pkg["Pkg"] = self.pkg_modify(pkg["Pkg"])
                pkg["Version"] = self.pkg_modify(pkg["Version"])
                pkglist.append(pkg["Pkg"] +':' + pkg["Version"])
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
            json.dump(pkg_vul,open(self.out_path + name + '.result','w'))
        conn.close()

    def deal(self,collector_log):
        global end_flag
        match = re.compile(self.pkg_match_str).findall(collector_log)
        if len(match) > 0:
            self.file_list.append(match[0])
            log.info("collector:Writing data into "+ match[0])
            logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "collector:Writing data into "+ match[0] + '\n')
        match = re.compile(self.loop_match_str).findall(collector_log)
        if len(match) > 0:
            end_flag = 1
        match = re.compile(self.nonew_match_str).findall(collector_log)
        if len(match) > 0:
            if end_flag == 1:
                os.popen("pkill collector")
                log.info("collecotr:Finish collecting")
                logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "collecotr:Finish collecting" + '\n')
                end_flag = 2
                if len(self.file_list) > 0:
                    self.pkg_analyse()
                else :
                    return
                log.info("collecotr:Finish analysing")
                logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "collecotr:Finish analysing" + '\n')
                log.info("collector:Stop Collector")
                logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "collector:Stop Collector" + '\n')
            else:
                end_flag = 0

    def collect(self):
        readlog = Tail(self.log_path)
        readlog.register_callback(self.deal)
        log.info("collector:Collecting data of %s"%self.repo)
        logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "collector:Collecting data of %s"%self.repo + '\n')
        readlog.follow(s=0.05)

def start_collector(repo):
    log.info("collector:Start Collector")
    logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "collector:Start Collector" + '\n')
    os.system("$GOPATH/bin/collector index.docker.io " + repo)

def container2id(name):
    containers = docker.Client().containers()
    for container in containers:
        if '/' + name in container["Names"]:
            return container["Id"]

def image2id(name):
    images = docker.Client().images()
    for image in images:
        if name in image["RepoTags"]:
            return image["Id"]

def nomask(ip):
    if '/' in ip:
        ip = ip[:ip.index('/')]
    return ip

class Image:
    def __init__(self, imageid, name, id, ip, mac, switch):
        self.imageid = imageid
        self.name = name
        self.id = id
        self.ip = ip
        self.mac = mac
        self.switch = switch
        self.info = {}
        self.funclist = []
        self.cvelist = {}

    def set_info(self,image_file):
        self.info = json.load(open(image_file,'r'))
    
    def set_cvelist(self):
        for pkg_info in self.info.values():
            for cve in pkg_info:
                self.cvelist[cve] = pkg_info[cve]

    def set_funclist(self,policy_path):
        policy_files = os.listdir(policy_path)
        policy = []
        for policy_file in policy_files:
            file = open(policy_path + policy_file,'r')
            policy = policy + file.readlines()
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
            imageid = self.imageid
            name = self.name
            id = self.id
            ip = self.ip
            for cmd in policy:
                if ("alert==0" not in cmd) and ("alert == 0" not in cmd):
                    continue
                cmd = cmd.replace('&&', ' and ')
                cmd = cmd.replace('||', ' or ')
                cmd = cmd.replace('!', ' not ')
                cmd = cmd.replace('IF', 'if')
                cmd = cmd.replace('  ',' ')
                cmd = cmd.replace("self",'''"{0}"'''.format(nomask(ip)))
                cmd = cmd.replace(' THEN ', ':\n')
                cmd = cmd.replace('[', "    funclist.append('self.")
                cmd = cmd.replace(',', "')\n    funclist.append('self.")
                cmd = cmd.replace(']', "')")
                cmd = cmd[:-1]
                exec cmd
        self.funclist = sorted(set(funclist),key=funclist.index)

def create_switch(name,ip):
    if '/' not in ip:
        ip = ip + DEFAULT_MASK
    os.system("ovs-vsctl add-br " + name)
    os.system("ip addr add " + ip + " dev " + name)
    os.system("ovs-vsctl set-controller " + name + " tcp:127.0.0.1:6633")
    log.info("OpenvSwitch:Switch {0} is created successfully".format(name))
    logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "OpenvSwitch:Switch {0} is created successfully".format(name) + '\n')
    info = os.popen("ovs-ofctl show " + name).read()
    dpid = info[info.index("dpid:")+5:info.index("dpid:")+21]
    switchlist[name] = (ip,int(dpid,16))

def delete_switch(name):
    containers = json.load(open(core.dans.web_path + "container.json", 'r'))
    for container in containerlist:
        if container.switch == name:
            delete_container(container.name)
            containers.pop(container.name)
    json.dump(containers, open(core.dans.web_path + "container.json", 'w'))
    os.system("ovs-vsctl del-br " + name)
    switchlist.pop(name)
    for switch in switchlist:
        os.popen("ovs-vsctl del-port " + switch + "-to-" + name)
    log.info("OpenvSwitch:Switch {0} is deleted successfully".format(name))
    logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "OpenvSwitch:Switch {0} is deleted successfully".format(name) + '\n')

def create_link(switch1, switch2):
    os.system("ovs-vsctl add-port " + switch1 + " " + switch1 + "-to-" + switch2)
    os.system("ovs-vsctl add-port " + switch2 + " " + switch2 + "-to-" + switch1)
    os.system("ovs-vsctl set interface " + switch1 + "-to-" + switch2 + " type=patch")
    os.system("ovs-vsctl set interface " + switch2 + "-to-" + switch1 + " type=patch")
    os.system("ovs-vsctl set interface " + switch1 + "-to-" + switch2 + " options:peer=" + switch2 + "-to-" + switch1)
    os.system("ovs-vsctl set interface " + switch2 + "-to-" + switch1 + " options:peer=" + switch1 + "-to-" + switch2)
    log.info("OpenvSwitch:Link between {0} and {1} is created successfully".format(switch1, switch2))
    logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "OpenvSwitch:Link between {0} and {1} is created successfully".format(switch1, switch2) + '\n')

def create_container(image, name, ip, mac, command, switch, info_path, policy_path):
    if '/' not in ip:
        ip = ip + DEFAULT_MASK
    log.info("Docker:Container {0} is created successfully".format(name))
    logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "Docker:Container {0} is created successfully".format(name) + '\n')
    os.popen("docker run -dit --net=none --name " + name + " " + image + " " + command)
    os.system("/home/dans/scripts/ovs-docker add-port "+switch+" eth0 "+name+" --ipaddress="+ip+" --macaddress="+mac)
    container = Image(image2id(image),name,container2id(name), ip, mac, switch)
    container.set_info(info_path + container.imageid[:12] + "-pkgdata.result")
    container.set_cvelist()
    container.set_funclist(policy_path)
    containerlist.append(container)
    interface = os.popen("ovs-vsctl --data=bare --no-heading --columns=name find interface external_ids:container_id=" + name).read()
    port = os.popen("ovs-vsctl get interface " + interface[:-1] + " ofport").read()
    core.dans.mactable[EthAddr(mac)] = (switchlist[switch][1],int(port))
    core.dans.iptable[IPAddr(nomask(ip))] = EthAddr(mac)

def delete_container(name):
    for container in containerlist:
        if container.name == name:
            core.dans.mactable.pop(EthAddr(container.mac))
            core.dans.iptable.pop(IPAddr(nomask(container.ip)))
            os.system("/home/dans/scripts/ovs-docker del-port "+container.switch+" eth0 "+container.name+" --ipaddress="+container.ip+" --macaddress="+container.mac)
            os.popen("docker rm -f " + name)
            containerlist.remove(container)
            log.info("Docker:Container {0} is deleted successfully".format(name))
            logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "Docker:Container {0} is deleted successfully".format(name) + '\n')
            return

def create_snort(switch, ip, mac):
    snort = docker.Client()
    log.info("Docker:Creating snort container {0} for {1}".format(switch + "snort", switch))
    logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "Docker:Creating snort container {0} for {1}".format(switch + "snort", switch) + '\n')
    switchip = switchlist[switch][0]
    switchip = nomask(switchip)
    snort.create_container(name=switch+"snort",tty=True,stdin_open=True,image="snort:test",command="/home/start.sh " + switchip + " 20000")
    snort.start(container = switch + "snort")
    os.system("/home/dans/scripts/ovs-docker add-port "+switch+" eth1 "+switch+"snort"+" --ipaddress="+ip+" --macaddress="+mac)
    interface = os.popen("ovs-vsctl --data=bare --no-heading --columns=name find interface external_ids:container_id=" + switch + "snort").read()
    ofport = os.popen("ovs-vsctl get interface " + interface[:-1] + " ofport").read()
    core.dans.mactable[EthAddr(mac)] = (switchlist[switch][1],int(ofport))
    snortlist[switchlist[switch][1]] = (ip,EthAddr(mac))
    core.dans.iptable[IPAddr(nomask(ip))] = EthAddr(mac)
    switch = core.openflow.getConnection(switchlist[switch][1])
    msg = of.ofp_flow_mod()
    msg.priority = LOW
    #msg.match.dl_type = 0x0800
    msg.match.dl_dst =  EthAddr(mac)
    msg.actions.append(of.ofp_action_output(port = int(ofport)))
    switch.send(msg)
    msg = of.ofp_flow_mod()
    msg.priority = LOW
    #msg.match.dl_type = 0x0800
    msg.match.dl_src = EthAddr(mac)
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    switch.send(msg)
    time.sleep(5)

def start_server(socket_map):
    """
    该函数在dans类中以子进程形式实现
    """
    asyncore.loop(map = socket_map)

def start_watch(wm, eh):
    """
    该函数在dans类中以子进程形式实现，需要两个参数，其中eh是改写的文件事件处理类
    """
    notifier = pyinotify.Notifier(wm, eh)
    notifier.loop()

class MyEventHandler(pyinotify.ProcessEvent):
    """
    改写后和策略相关函数结合的文件系统事件处理类
    """
    log.info("Starting monitor to policy_path...")
    logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "Starting monitor to policy_path..." + '\n')
    def gen_cmd(self, pathname):
        """
        读取pathname路径文件中的内容，即如入策略文件中的策略
        """
        try:
            fd = open(pathname, 'r')
            commands = fd.readlines(MAXCMD)
            fd.close()     #返回值是策略列表
            return commands
        except IOError as e:
            log.error("I/O error ({0}): {1}".format(e.errno, e.strerror))
        return -1
    def func_gen(self, event):
        """
        根据gen_cmd的返回值，生成策略函数，注意该函数调用了dans类中的对应函数以及
        dans类中的func_table,其数据结构如下：
        {priority:{signatrue:{(interval, times):funcname}}}
        """
        commands = self.gen_cmd(event.pathname)
        if not commands == -1:
            core.dans.func_gen(event.name, commands)
    def func_del(self, event):
        """
        与上一方法相反，该方法是在策略文件被移走或删除时删除原来的策略函数，删除过程
        与生成过程恰好相反
        """
        func_name = "func_" + event.name
        try:
            funcname = func_name.replace(" ", "_")
            core.dans.funclist.remove(func_name)
            delattr(core.dans.handlers, funcname)
            log.info("handler %s removed, rules updated."%funcname)
            logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "handler %s removed, rules updated."%funcname + '\n')
        except ValueError:
            log.error('%s is not in the funclist'%func_name)
    #剩下的方法，全部是重载父类的方法，将文件系统事件与策略函数的生成与删除联系
    def process_IN_MOVED_TO(self, event):
        log.debug('MOVED_TO event: %s'%event.name)
        self.func_gen(event)
    def process_IN_MODIFY(self, event):
        log.debug('MODIFY event: %s'%event.name)
        self.func_del(event)
        self.func_gen(event)
    def process_IN_DELETE(self, event):
        log.debug('DELETE event: %s'%event.name)
        self.func_del(event)
    def process_IN_MOVED_FROM(self, event):
        log.debug('MOVED_FROM event: %s', event.name)
        self.func_del(event)

class AlertIn(revent.Event):
    """
    按照pox的wiki，通过继承revent.Event类自定义事件
    """
    def __init__(self, alertmsg):
        """
        事件初始化，参数为alertmsg列表
        """
        revent.Event.__init__(self)     #先调用父类的初始化
        self.name = alertmsg[0]
        self.priority = alertmsg[1]
        self.src = alertmsg[2]
        self.dst = alertmsg[3]
        self.occation  = alertmsg[4]

class Reminder(revent.EventMixin):
    """
    该类用于触发自定义事件
    """
    _eventMixin_events = set([
        AlertIn,
        ])
    def __init__(self):
        self.msg = None
    def set_msg(self, msg):
        self.msg = msg
    def alert(self):
        self.raiseEvent(AlertIn, self.msg)

class dans_connect(asynchat.async_chat):
    """
    通过继承asynchat.async_chat类，该类用于处理从指定socket接收到的数据，
    即处理传送的报警信息
    """
    def __init__(self, connection, socket_map):
        #先调用父类类初始化
        asynchat.async_chat.__init__(self, connection, map = socket_map)
        self.buf = []
        self.ac_in_buffer_size = 1024
        self.set_terminator("@")     #设置断点
    def collect_incoming_data(self, data):
        self.buf.append(data)
    def found_terminator(self):
        """
        根据断点逐条读取报警信息
        """
        temp = ("".join(self.buf)).split("\n")
        core.Reminder.set_msg(temp)
        core.Reminder.alert()
        self.buf=[]
        self.set_terminator("@")

class dans_server(asyncore.dispatcher):
    """
    通过继承asyncore.dispatcher类，该类用于与远端socket建立连接，即与远端Snort 
    IDS建立通信通道
    """
    def __init__(self, socket_map):
        self.socket_map = socket_map
        # 先调用父类类初始化
        asyncore.dispatcher.__init__(self, map = self.socket_map)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind(("0.0.0.0",20000))     #开放端口供远端Snort IDS连接
        self.listen(5)
    def handle_accept(self):
        connection, addr = self.accept()
        # 调用dans_connect类来处理接收到的数据
        server_connect = dans_connect(connection, self.socket_map)
        server_connect

class handlers(object):
    """
    所有策略函数是该类的属性
    """
    def __init__(self):
        pass

class dans(object):

    """
    本程序的核心类 负责各方通信与事件处理
    """

    def start(self):
        """
        初始化：添加监听
        """
        core.openflow.addListeners(self)
        core.openflow_discovery.addListeners(self)

    def __init__(self, path):
        """
        初始化：对dans的属性进行赋值初始化并调用一些方法初始化
        """
        self.path = path     #被监视文件系统的路径
        self.web_path = "/home/dans/last/"
        self.filelist=None     #所监视文件路径下的文件列表
        self.counter=0     #文件计数器
        self.filenum=0     #len(self.filelist)
        # 命令列表（也是策略函数的基本组成部分）
        self.cmdlist = ["output", "disconnect", "wait", "reconnect", "monitor", \
                        "reset", "redirect", "unredirect", "passit", "refuse"]
        self.handlers = handlers()     #外部类的一个实例
        self.funclist = None     #策略函数名列表
        self.alys_cmd()     #对策略文件初始化处理
        self.action_triggered = False 
        self.mactable = {}     #用于储存网络结点的信息
        #其数据结构为{"MacAddr":(switchid,port)}
        self.iptable = {}     #用于储存网络结点Mac地址对应的IP
        #其数句结构为{"IPAddr":"MacAddr"}
        self.droplist = {}    #被disconnect的名单列表
        self.monitorlist = {}    #被monitor的名单列表
        self.redirectlist = {}     #被redirect的名单列表
        self.ignorelist = []     #被忽略的名单列表
        self.dangerlist = {}
        self.blacklist = {}
        self.socket_map = {}     #start_server的参数
        self.server = dans_server(self.socket_map)
        thread.start_new_thread(self.start_webserver,())
        #pox的初始化
        core.Reminder.addListeners(self)     
        core.addListener(pox.core.GoingUpEvent, self.start_server)
        core.call_when_ready(self.start, ["openflow_discovery"])
        core.callDelayed(-3, self.start_watch)   
        
        self.db_path = "/home/dans/database/cve.db"
        self.cache_path = "/home/dans/result/dans/"
        self.repo = "dracula36/dans"
        
        #thread.start_new_thread(start_collector,(self.repo, ))
        #self.col = collector(self.db_path, self.cache_path, self.repo)
        #self.col.collect()

        log.info("Dans module launched.")
        logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "Dans module launched." + '\n')

    def detect_container(self,switch):
        for container in containerlist:
            if container.switch == switch:
                log.info("Detecting container {0} (ip:{1} id:{2})".format(container.name,container.ip,container.id))
                logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "Detecting container {0} (ip:{1} id:{2})".format(container.name,container.ip,container.id) + '\n')
                for func in container.funclist:
                    exec func

    def get_cve(self,switch):
        cve_list = []
        log.info("Geting total cve data from all containers")
        logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "Geting total cve data from all containers" + '\n')
        for container in containerlist:
            if container.switch == switch:
                cve_list += container.cvelist
        return sorted(set(cve_list),key=cve_list.index)

    def start_server(self, event):
        """
        初始化：以子进程建立与Snort IDS的通信
        """
        thread.start_new_thread(start_server, (self.socket_map,))

    def start_client(self,snort_ip,data):
        for each in data:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((snort_ip, 8001))
            sock.send(each)
            sock.close()
        log.info("snort:Sending CVE data to Snort and distribute rules for Snort")
        logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "snort:Sending CVE data to Snort and distribute rules for Snort" + '\n')

    def start_snort(self,snort_ip):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((snort_ip, 8002))
        sock.send("start")
        sock.close()
        log.info("snort:Start Snort")
        logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "snort:Start Snort" + '\n')

    def start_webserver(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', 8003))
        sock.listen(5)
        log.info("start web server")
        logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "start web server" + '\n')
        while True:
            connection,address = sock.accept()
            rec = connection.recv(1024).decode('utf-8')
            instruct = rec[:rec.index('_')]
            name = rec[rec.index('_') + 1:]
            if instruct == "add-container":
                info = json.load(open(self.web_path + "container.json",'r'))
                new = info[name]
                create_container(new["image"], new["name"], new["ip"],self.ip2mac(new["ip"]),new["command"],new["connect"],self.cache_path,self.path)
            elif instruct == "add-switch":
                info = json.load(open(self.web_path + "switch.json",'r'))
                new = info[name]
                connectlist = new.keys()
                connectlist.remove("name")
                connectlist.remove("ip")
                create_switch(new["name"],new["ip"])
                if len(connectlist) != 0:
                    for switch in connectlist:
                        create_link(new["name"],switch)
            elif instruct == "del-container":
                delete_container(name)    
            elif instruct == "del-switch":
                delete_switch(name)    
            connection.close()


    def start_watch(self):
        """
        初始化：以子进程监听文件是系统
        """
        wm = pyinotify.WatchManager()
        wm.add_watch(self.path, pyinotify.ALL_EVENTS, rec = True)
        eh = MyEventHandler()
        thread.start_new_thread(start_watch, (wm, eh))

    def ip2mac(self,ip):
        num = reduce(lambda x,y:(x<<8)+y,map(int,nomask(ip).split('.'))) 
        str = hex(num)[2:]
        str = "0" * (12 - len(str)) + str
        return str[:2] + ':' + str[2:4] + ':' + str[4:6] + ':' + str[6:8] + ':' + str[8:10] + ':' + str[10:12] 

    def func_gen(self, File, cmds):
        """
        根据形参cmds生成策略函数
        """
        func_name = "func_" + File
        self.funclist.append(func_name)
        func_name = func_name.replace(" ", "_")     #从策略名到函数名
        cmdgenlist = []
        #将cmds的策略转化为函数语句
        for cmd in cmds:
            if "alert==0" in cmd or "alert == 0" in cmd:
                continue
            cmd = cmd.replace('&&', ' and ')
            cmd = cmd.replace('||', ' or ')
            cmd = cmd.replace('!', ' not ')
            cmd = cmd.replace('IF', 'if')
            condition = cmd[:cmd.index('THEN')]
            result = cmd[cmd.index('THEN'):]
            if 'trigger' in condition:
                middle = condition.index(',')
                condition = condition[:middle] + "), occation, src, dst) >= " + condition[middle+1:]
                condition = condition.replace('trigger(', '(self.sql(self.occa_process(occation, ')
            condition = condition.replace('  ',' ')
            condition = condition[:-1]
            result = result.replace('THEN ', ':\n')
            result = result.replace('[', "        self.")
            result = result.replace(',', "\n        self.")
            result = result.replace(']', "")
            cmd = condition + result
            cmd = cmd[:-1]
            cmdgenlist.append(cmd)
        #function相当于定义一个函数的代码
        function = "def "+func_name+"(self, src, dst, alert, occation, priority):\n"
        for command in cmdgenlist:
           function = function+"    "+command+"\n"
        exec function  
        #将策略函数作为handlers这个类的一个属性
        setattr(self.handlers, func_name, eval(func_name))
        log.info("handler %s registered, rules updated."%func_name)
        logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "handler %s registered, rules updated."%func_name + '\n')

    def alys_file(self):
        """
        读取类成员filelist中的文件
        """
        for File in self.filelist:
            fd = open(self.path + File,'r')
            commands = fd.readlines(MAXCMD)
            fd.close()
            yield File, commands     #迭代器的使用

    def alys_cmd(self):
        """
        通过调用func_gen()与alys_file()完成将指定路径下所有
        的策略文件全部转化为策略函数
        """
        self.filelist = os.listdir(self.path)     #获取策略文件夹结构
        self.funclist = []
        self.filenum = len(self.filelist)
        filegen = self.alys_file()     #迭代调用alys_file()
        while self.counter < self.filenum:
            File,commands = filegen.next()
            self.func_gen(File, commands)     #调用func_gen()
            self.counter += 1

    def output(self,str):
        log.info("output:%s"%str)
        logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "output:%s"%str + '\n')

    def passit(self):
        """
        跳过该动作，即什么都不执行
        """
        self.action_triggered = True     #动作开关变为开

    def connect(self,addr):
        self.action_triggered = False
        ipaddr = IPAddr(addr)
        macaddr = self.iptable[ipaddr]
        switch = core.openflow.getConnection(self.mactable[self.iptable[ipaddr]][0])
        msg = of.ofp_flow_mod()
        msg.priority = LOW
        #msg.match.dl_type = 0x0800
        msg.match.dl_dst = macaddr
        msg.actions.append(of.ofp_action_output(port = self.mactable[self.iptable[ipaddr]][1]))
        switch.send(msg)
        msg = of.ofp_flow_mod()
        msg.priority = LOW
        #msg.match.dl_type = 0x0800
        msg.match.dl_src = macaddr
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        switch.send(msg)
        self.action_triggered = True     #将动作开关置为开

    def disconnect(self,addr):
        """
        切断所给IP流量的流入流出
        """
        self.action_triggered = False     #先将动作开关置为关
        #判断所给addr是否在droplisit中，如果在，对应值加1
        if self.droplist.has_key(addr):
            self.droplist[addr] += 1
        else:
            self.droplist[addr] = 1
        if self.droplist[addr] != 1:
            return
        ipaddr = IPAddr(addr)     #地址转换
        snort_mac = snortlist[self.mactable[self.iptable[ipaddr]][0]][1]
        msg = of.ofp_flow_mod()
        msg.priority = MID     #设置安全级别，也就是流表的优先级
        if self.iptable.has_key(ipaddr) and self.iptable[ipaddr] != snort_mac:
            #阻断内网机器的流量
            host_mac = self.iptable[ipaddr]
            switchid = self.mactable[host_mac][0]
            msg.match.dl_type = 0x0800
            msg.match.dl_src = host_mac
            #具体的阻断通过OFPP_NONE实现
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
        else:
            switchid = self.mactable[snort_mac][0]
            msg.match.dl_type = 0x0800
            msg.match.nw_src = ipaddr
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
        switch = core.openflow.getConnection(switchid)
        switch.send(msg)
        self.action_triggered = True     #将动作开关置为开
        log.info("%s being disconncted"%addr)
        logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "%s being disconncted"%addr + '\n')

    def refuse(self,addr):
        self.action_triggered = False
        for snort_dpid in snortlist.keys():
            msg = of.ofp_flow_mod()
            msg.priority = HIGHER
            msg.match.dl_type = 0x0800
            msg.match.nw_src = IPAddr(addr)
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            core.openflow.getConnection(snort_dpid).send(msg)
            #self.blacklist[ip] = 1;
            log.info("all the request of %s being refused"%addr)
            logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "all the request of %s being refused"%addr + '\n')
        self.action_triggered = True


    def redirect(self,addr):
        """
        在某台内网机器被disconnect后将被阻断流量重定向到另一台机器
        """
        self.action_triggered = False     #先将动作开关置为关
        ipaddr = IPAddr(addr)
        snort_mac = snortlist[self.mactable[self.iptable[ipaddr]][0]][1]
        #判断所给ip是否提供网络服务
        if not ip2serv_name.has_key(addr):
            return
        #判断所给ip是否在redirectlist中，如果在，值加1
        if self.redirectlist.has_key(addr):
            self.redirectlist[addr] += 1
        else:
            self.redirectlist[addr] = 1
        if self.redirectlist[addr] == 1:
            if self.droplist.has_key(addr):
                if ip2serv_name.has_key(addr):
                    serv_name = ip2serv_name[addr]
                    if serv_name2ip.has_key(serv_name):
                    	Masterip = serv_name2ip[serv_name][0]     #定义主服务器
                    	Masteraddr = IPAddr(Masterip)
                        livelist = [ item for item in serv_name2ip[serv_name] if item not in self.droplist ]
                        if len(livelist) > 0:
                            new_ip = random.choice(livelist)     #在可用备用服务器中随机选择一台
                            log.info("redirecting for %s to %s in the service of %s"%(addr, str(new_ip), serv_name))
                            logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "redirecting for %s to %s in the service of %s"%(addr, str(new_ip), serv_name) + '\n')
                            new_mac = self.iptable[IPAddr(new_ip)]
                            #流表处理
                            msg = of.ofp_flow_mod()
                            msg.match.dl_dst = self.iptable[Masteraddr]
                            msg.actions.append(of.ofp_action_dl_addr.set_dst(new_mac))
                            msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(new_ip)))
                            msg.priority = HIGH      #设置安全级别，即优先级
                            routelist = get_shortest_route(pox.openflow.spanning_tree._calc_spanning_tree(), self.mactable[snort_mac][0], self.mactable[new_mac][0])
                            routelist[-1] = self.mactable[new_mac]
                            msg.actions.append(of.ofp_action_output(port = routelist[0][1]))
                            switchid = self.mactable[snort_mac][0]
                            switch = core.openflow.getConnection(switchid)
                            switch.send(msg)
                            #流表处理
                            msg = of.ofp_flow_mod()
                            msg.match.dl_src = self.iptable[IPAddr(new_ip)]
                            msg.match.dl_dst = snort_mac
                            msg.priority = HIGH
                            msg.actions.append(of.ofp_action_dl_addr.set_src(self.iptable[ipaddr]))
                            msg.actions.append(of.ofp_action_nw_addr.set_src(ipaddr))
                            msg.actions.append(of.ofp_action_output(port = self.mactable[snort_mac][1]))
                            switchid = self.mactable[snort_mac][0]
                            switch = core.openflow.getConnection(switchid)
                            switch.send(msg)
                            self.action_triggered = True
                        else:
                            log.error("no more same service ip to redirect")
                    else:
                        log.error("check the service to ip dictionary %s"%serv_name)
                else:
                    log.error("check the ip to service dictionary %s"%addr)
            else:
                log.error("%s is not in droplist"%addr)

    def wait(self,arg):
        """
        等待指定时间，相当于休眠
        """
        log.info("waiting for %d seconds"%arg)
        logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "waiting for %d seconds"%arg + '\n')
        time.sleep(arg)     #调用系统的time类函数

    def reconnect(self,addr):
        """
        解除disconnect
        """
        self.action_triggered = False     #先将动作开关置为关
        snort_mac = snortlist[self.mactable[self.iptable[IPAddr(addr)]][0]][1]
        self.droplist[addr] -= 1     #其droplist中对应值减1
        if self.droplist[addr] <= 0:
            ipaddr = IPAddr(addr)
            self.droplist[addr] = 0
            log.info("%s being reconnected"%addr)
            logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "%s being reconnected"%addr + '\n')
            #流表处理
            msg = of.ofp_flow_mod()
            msg.command = of.OFPFC_DELETE_STRICT      #通过删除相关流表实现
            msg.priority = MID     #设置安全级别，即优先级
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            if self.iptable.has_key(ipaddr) and self.iptable[ipaddr] != snort_mac:
                host_mac = self.iptable[ipaddr]
                switchid = self.mactable[host_mac][0]
                msg.match.dl_type = 0x0800
                msg.match.dl_src = host_mac
            else:
                switchid = self.mactable[snort_mac][0]
                msg.match.dl_type = 0x0800
                msg.match.nw_src = ipaddr
            switch = core.openflow.getConnection(switchid)
            switch.send(msg)
            self.action_triggered = True     #将动作开关置为开

    def monitor(self, addr):
        """
        监视指定IP的流量
        """
        self.action_triggered = False     #先将动作开关置为关
        ipaddr = IPAddr(addr)
        snort_mac = snortlist[self.mactable[self.iptable[ipaddr]][0]][1]
        if not self.iptable.has_key(ipaddr):
            return
        if self.iptable[ipaddr] == snort_mac:
            return
        #判断所给ip是否在monitorlist中，如果在，值加1
        if self.monitorlist.has_key(addr):
            self.monitorlist[addr] += 1
        else:
            self.monitorlist[addr] = 1
        if self.monitorlist[addr] == 1:
            #流表处理
            msg = of.ofp_flow_mod()
            msg.priority = LOWMID
            msg.match.dl_dst = self.iptable[ipaddr]
            #msg.match.dl_type = 0x0800
            #msg.actions.append(of.ofp_action_dl_addr.set_dst(snort_mac))
            #调用全局函数计算最短路由
            routelist = get_shortest_route(pox.openflow.spanning_tree._calc_spanning_tree(), self.mactable[self.iptable[ipaddr]][0], self.mactable[snort_mac][0])
            routelist[-1] = self.mactable[snort_mac]
            #根据最短路由设置流表
            msg.actions.append(of.ofp_action_output(port = routelist[0][1]))
            msg.actions.append(of.ofp_action_output(port = self.mactable[self.iptable[ipaddr]][1]))
            switchid = self.mactable[self.iptable[ipaddr]][0]
            switch = core.openflow.getConnection(switchid)
            switch.send(msg)
            self.action_triggered = True     #将动作开关置为开
            log.info("packet from/to %s mirrored for monitoring"%addr)
            logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "packet from/to %s mirrored for monitoring"%addr + '\n')

    def reset(self, addr):
        """
        重置曾经对所给IP的策略动作
        """
        self.action_triggered = False     #先将动作开关置为关
        self.monitorlist[addr] -= 1
        if self.monitorlist[addr] > 0:
            return
        self.monitorlist[addr] = 0
        log.info("resetting %s"%addr)
        logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "resetting %s"%addr + '\n')
        #流表处理
        msg = of.ofp_flow_mod()
        msg.command = of.OFPFC_DELETE_STRICT     #具体实现通过删除相关流表
        ipaddr = IPAddr(addr)
        host_mac = self.iptable[ipaddr]
        msg.match.dl_src = host_mac
        switchid = self.mactable[host_mac][0]
        switch = core.openflow.getConnection(switchid)
        switch.send(msg)
        self.action_triggered = True     #将动作开关置为开

    def unredirect(self, addr):
        """
        解除redirect
        """
        snort_mac = snortlist[self.mactable[self.iptable[IPAddr(addr)]][0]][1]
        self.action_triggered = False     #先将动作开关置为关
        self.redirectlist[addr] -= 1     #redirectlist中对应值减1
        if self.redirectlist[addr] > 0:
            return
        self.redirectlist[addr] = 0
        log.info("unredirecting %s"%addr)
        logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "unredirecting %s"%addr + '\n')
        #流表处理
        msg = of.ofp_flow_mod()
        msg.command = of.OFPFC_DELETE_STRICT     #具体实现通过删除相关流表
        msg.priority = HIGHER
        serv_name = ip2serv_name[addr]
        Masterip = serv_name2ip[serv_name][0]     #定义主服务器
        Masteraddr = IPAddr(Masterip)
        host_mac = self.iptable[Masteraddr]
        msg.match.dl_dst = host_mac
        msg.match.of_ip_src = Masterip
        switchid = self.mactable[snort_mac][0]
        switch = core.openflow.getConnection(switchid)
        switch.send(msg)
        self.action_triggered = True

    def occa_process(self, occation, during):
        """
        对AlertIn传来的occation参数和策略文件中提供的
        time参数进行处理
        """
        #调用系统的time库来对时间进行相关处理
        timeArray = time.strptime(occation, "%Y/%m/%d-%H:%M:%S")
        timeStamp = time.mktime(timeArray)
        timeStamp -= float(during)
        timeArray = time.localtime(timeStamp)
        before = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)  
        #根据sql()的需要返回一个时间参数
        return before

    def _handle_AlertIn(self, event):
        """
        对AlertIn的相应和处理，并进行策略匹配
        """
        log.info("Alert In.")     #向pox内核日志发送报警信息
        logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "Alert In." + '\n')     #向pox内核日志发送报警信息
        #获取event参数
        alert = event.name
        occation = event.occation
        priority = event.priority
        sip  = event.src
        dip  = event.dst
        log.info("AlertName:{0} SourceIP:{1} DestIP:{2}".format(alert,sip,dip))
        logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "AlertName:{0} SourceIP:{1} DestIP:{2}".format(alert,sip,dip) + '\n')
        #判断来源IP所在主机是否被攻击
        if ip2serv_name.has_key(dip) and not self.dangerlist.has_key(dip):
            self.dangerlist[dip] = sip;
        if self.dangerlist.has_key(sip) and not self.blacklist.has_key(self.dangerlist[sip]):
            self.blacklist[self.dangerlist[sip]] = 0;

        if self.monitorlist.has_key(sip) and self.monitorlist[sip] > 0 and not alert in self.ignorelist:
            log.info("%s is under attack and may have been captured, so disconncet it."%sip)
            logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "%s is under attack and may have been captured, so disconncet it."%sip + '\n')
            self.disconnect(sip)     #断掉被攻击主机
        #以子进程触发对应策略函数
        for func in self.funclist:
            new_th = threading.Thread(target = getattr(self.handlers, func), args=(self, sip, dip, alert, occation, priority))
            new_th.start()

    def sql(self, before, occation, src, dst):
        """
        通过调取mysql数据库中snort这个database里的信息，
        反馈某事件过去某时间段内发生的次数
        """
        occation = time.strftime("%Y-%m-%d %H:%M:%S", time.strptime(occation, "%Y/%m/%d-%H:%M:%S"))
        snort_ip = nomask(snortlist[self.mactable[self.iptable[IPAddr(dst)]][0]][0])
        #连接数据库
        try:
            conn = mysql.connector.connect(host=snort_ip, user='root',passwd='root',db='snort')
        except Exception, e:
           log.error(e)
        cursor = conn.cursor()
        #执行数据库命令进行查询
        cursor.execute("select count(*) as times from iphdr,event where (event.timestamp between '%s' and '%s') and (iphdr.ip_src=%d and iphdr.ip_dst=%d) and iphdr.cid=event.cid;"%(before, occation, socket.ntohl(struct.unpack("I", socket.inet_aton(src))[0]), socket.ntohl(struct.unpack("I", socket.inet_aton(dst))[0])))
        #保存查询结果
        rows = cursor.fetchone()
        #关闭数据库并断开与数据库的连接
        cursor.close()
        conn.close()
        log.info("between {0} and {1} this alert was triggered {2} times".format(before,occation,rows[0]))
        logwrite(time.strftime("[%Y-%m-%d %H:%M:%S]") + "between {0} and {1} this alert was triggered {2} times".format(before,occation,rows[0]) + '\n')
        #返回查询结果
        return rows[0]

    def gen_homenet(self,switch):
        homenet = "["
        for container in containerlist:
            if container.switch == switch:
                homenet = homenet + container.ip + ','
        homenet = homenet[:-1] + ']'
        return homenet

    """
    def _handle_ConnectionUp(self, event):
        for each in switchlist.keys():
            if switchlist[each][1] == event.dpid:
                switch = each
                switch_ip = switchlist[each][0]
        mask = switch_ip[switch_ip.index('/'):]
        snort_ip = '.'.join([str((reduce(lambda x,y:(x<<8)+y,map(int,nomask(switch_ip).split('.'))) +1 )/(256**i)%256) for i in range(3,-1,-1)])
        snort_mac = self.ip2mac(snort_ip)
        snort_ip = snort_ip + mask
        snortlist[event.dpid] = (snort_ip,snort_mac)
        create_snort(switch, snort_ip, str(snort_mac))
        #self.start_client(nomask(snort_ip), self.get_cve(switch) + [self.gen_homenet(switch)])
        #self.start_snort(nomask(snort_ip))
        #self.detect_container(switch)
    """

def launch():
    """
    启动组件
    """
    open(logfile,'w').close()
    pox.openflow.discovery.launch()
    path = "/home/dans/pox/dans/rules/"     #指定策略文件夹路径
    core.registerNew(Reminder)     #向pox内核注册Reminder类
    core.registerNew(dans, path)     #向pox内核注册dans类
    #create_switch("switch","10.0.0.10/24")
    #create_container("server:ubuntu", "httpserver", "10.0.0.1/24", "00:00:00:00:00:01", "/home/start.sh", "switch", core.dans.cache_path, core.dans.path)
    #create_container("server:ubuntu", "backserver", "10.0.0.2/24", "00:00:00:00:00:02", "/home/start.sh", "switch", core.dans.cache_path, core.dans.path)
    #create_switch("extern","10.0.0.20/24")
    #create_link("switch","extern")
    #create_container("server:ubuntu", "extern", "10.0.0.101/24", "00:00:00:00:01:01", "/bin/bash", "extern", core.dans.cache_path, core.dans.path)
