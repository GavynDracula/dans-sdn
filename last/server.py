#coding:utf-8

from flask import Flask, render_template, request, send_file
import json
import socket
import time
import docker

class Client(object):
    def __init__(self, host='127.0.0.1', port=8003):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    def command(self, instruct, name=''):
        #1-add_container, 2-add_switch, 3-del_container, 4-del_swith, 5-add_policy
        try:
            self.sock.connect((self.host, self.port))
            self.sock.send(instruct + '_' + name)
            self.sock.close()
            time.sleep(2)
        except Exception, e:
            self.error(e)

    def error(self, e):
        print e
        print 'Failed to connect with the server ' + self.host + ':' + str(self.port)

app = Flask(__name__)
app.config['container'] = './container.json'
app.config['switch'] = './switch.json'
app.config['log'] = '/home/dans/pox/dans/log/danslog'
app.config['policy'] = '/home/dans/pox/dans/rules/policy'

def get_switch_name():
    try:
        name = json.load(file(app.config['switch'])).keys()
    except:
        name = []
    return name

def get_container_name():
    try:
        name = json.load(file(app.config['container'])).keys()
    except:
        name = []
    return name

def get_log():
    with open(app.config['log']) as f:
        logs = f.readlines()[::-1]
        infos = []
        for log in logs:
            info = (log[1:20], log[21:])
            infos.append(info)
        return infos

def get_policy():
    with open(app.config['policy']) as f:
        infos = f.readlines()
        return infos

@app.route('/')
@app.route('/index/')
def show_topo():
    return render_template('index.html')

@app.route('/add-container/', methods=['POST', 'GET'])
def add_container():
    if request.method == 'POST':
        try:
            origin = json.load(open(app.config['container'], 'r'))
        except:
            origin = {}
        form = request.form
        origin[form['name']] = form
        json.dump(origin, open(app.config['container'], 'w'))
        Client().command("add-container", form['name'])
    images = docker.Client().images()
    names = [ image['RepoTags'] for image in images ]
    return render_template('add-container.html', switches=get_switch_name(), names=names)

@app.route('/add-switch/', methods=['POST', 'GET']) 
def add_switch(): 
    if request.method == 'POST':
        try:
            origin = json.load(open(app.config['switch'], 'r'))
        except:
            origin = {}
        form = request.form
        origin[form['name']] = form
        json.dump(origin, open(app.config['switch'], 'w'))
        Client().command("add-switch", form['name'])
    return render_template('add-switch.html', switches=get_switch_name())

@app.route('/del-container/', methods=['POST', 'GET'])
def del_container():
    if request.method == 'POST':
        origin = json.load(open(app.config['container'], 'r'))
        name = request.form['aim']
        origin.pop(name)
        Client().command("del-container", name)
        json.dump(origin, open(app.config['container'], 'w'))
    return render_template('del-container.html', containers=get_container_name())

@app.route('/del-switch/', methods=['POST', 'GET'])
def del_swith():
    if request.method == 'POST':
        origin = json.load(open(app.config['switch'], 'r'))
        name = request.form['aim']
        origin.pop(name)
        Client().command("del-switch", name)
        json.dump(origin, open(app.config['switch'], 'w'))
    return render_template('del-switch.html', switches=get_switch_name())

@app.route('/log/')
def log():
    infos = get_log()
    return render_template('log.html', infos=infos)

@app.route('/rule/')
def policy():
    infos = get_policy()
    return render_template('policy.html', infos=infos)

@app.route('/add_policy/', methods=['POST'])
def add_policy():
    if request.method == 'POST':
        policy = request.form['policy']
        f = open(app.config['policy'], 'a')
        f.write(policy)
        f.write('\n')
        f.close()
        Client().command('add_policy')
        infos = get_policy()
    return render_template('policy.html', infos=infos)

@app.route('/switch.json')
def switch_json():
    return send_file('switch.json')

@app.route('/container.json')
def container_json():
    return send_file('container.json')

if __name__ == '__main__':
    app.run(debug=True,host="0.0.0.0")
