import os
import json

input_path = "ubuntu/"
info_list = (json.load(open(input_path + "metadata.json",'r'))).values()[1]
image_list = {}
for info in info_list:
    image_list[info["Image"][:12]] = info["Repo"] + ":" + info["Tag"]

json_list = os.listdir(input_path + "result")
for json_f in json_list:
    image = json_f[:12]
    instruct = "mv {0} {1}".format(input_path + "result/" + json_f, input_path + "result/" + image_list[image] + "-pkgdata.result")
    os.popen(instruct)
