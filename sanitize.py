# This script can be used to sanitize logs from crowdstrike
# dictionary.json file should include a lookup dictionary for str replace
import json
import io
import re
import hashlib
import random
import socket
import struct

original_file = "detections.json"
results_file = "output.json"
static_dictionary_file = "dictionary.json"


def is_json(myjson):
  try:
    json.loads(myjson)
    print("[DEBUG] Data source is a Valid JSON")
  except ValueError as e:
    print("[ERROR] Data source is NOT a Valid JSON")
    return False
  return True


def output_json(_data):
    print("writing {} lines to '{}'".format(len(_data), results_file))
    f = open(results_file, "w")
    f.write(_data)
    f.close()

def sub_with_dict(_dict, _list):
    print("[INFO] Processing dictionary with {} items".format(len(_dict)))
    cache = []
    line_count = 0
    replace_count = 0
    for line in _list:
        line_count = line_count + 1

        newline = line.strip().lower()
        #check dictionary to see if there any string matches.
        for key,val in _dict.items():
            key = key.lower()
            if key in newline:
                newline = newline.replace(key,val)
                replace_count = replace_count + 1
                #print("UPDATE Line {} ({} -> {}): {}".format(line_count, key, val, newline))

        cache.append(newline)

    print("[INFO] Replaced {} items".format(replace_count))

    return cache

#load source
print("[INFO] Rading Data source '{}'".format(original_file))
file = open(original_file, "r")
content_list = file.readlines()
print("[INFO] Read {} lines".format(len(content_list)))
is_json("".join(content_list))

#load static dictionary
print("[INFO] Loading dictianry '{}'".format(static_dictionary_file))
with open(static_dictionary_file) as json_file:
    static_dictionary = json.load(json_file)

#print("[DEBUG] {}".format(static_dictionary))
print("")

print("[INFO] Dictionary Anonimization")
content_list = sub_with_dict(static_dictionary, content_list)

#result_json = join_noesc(content_list)
#print(type(result_json))
#is_json("".join(content_list))
#print(json.dumps(json.loads("".join(content_list)), indent=3))

#exit()
print("[INFO] Anonymizing hostname")
list_hostname = []
data_json = json.loads("".join(content_list))
for item in data_json:
    if item["device"]["hostname"] not in list_hostname:
        #md5hash = print(hashlib.md5(item["device"]["hostname"].encode('utf-8')).hexdigest())
        list_hostname.append(item["device"]["hostname"])
dict_host = {}
for host in list_hostname:
    md5hash = (hashlib.md5(host.encode('utf-8')).hexdigest())
    #dict_host.append({item["device"]["hostname"]:"host-{}".format(md5hash[:6])})
    dict_host[host] = "host-{}".format(md5hash[-6:])

#print(dict_host)
content_list = sub_with_dict(dict_host, content_list)


print("[INFO] Anonymizing External IPs")
list_ext_ips = []
data_json = json.loads("".join(content_list))
for item in data_json:
    if item["device"]["external_ip"] not in list_ext_ips:
        #md5hash = print(hashlib.md5(item["device"]["hostname"].encode('utf-8')).hexdigest())
        list_ext_ips.append(item["device"]["external_ip"])
#print(list_ext_ips)
dict_ext_ips = {}
for ip in list_ext_ips:
    ip_md5hash = (hashlib.md5(ip.encode('utf-8')).hexdigest())
    new_ip = socket.inet_ntoa(struct.pack('>I', int("0x{}".format(ip_md5hash[-8:]), 16)))
    dict_ext_ips[ip] = new_ip
#print(dict_ext_ips)
content_list = sub_with_dict(dict_ext_ips, content_list)

print("[INFO] Anonymizing Usernames")
list_usernames = []
#Check Structured
data_json = json.loads("".join(content_list))
for item in data_json:
    username = item["behaviors"][0]["user_name"]
    if username not in list_usernames:
        #md5hash = print(hashlib.md5(item["device"]["hostname"].encode('utf-8')).hexdigest())
        list_usernames.append(username)

#print(list_usernames)
#check unstractures
#Userdir
re_userdir = r'users[\/\\](.+?)[\/\\]'
for row in content_list:
    search = re.findall(re_userdir, row, re.IGNORECASE)
    if search:
        #print(search)
        for item in search:
            if item.replace("\\","") not in list_usernames:
                #print(item.replace("\\",""))
                list_usernames.append(item.replace("\\",""))

print(list_usernames)
dict_usernames = {}
for user in list_usernames:
    if not user:
        continue
    #special case for root..
    if user == 'root':
        dict_usernames[user] = user
        continue

    user_md5hash = (hashlib.md5(user.encode('utf-8')).hexdigest())
    dict_usernames[user] = "user-{}".format(user_md5hash[-6:])
    #replace_period_w_underscore for url matching
    if "." in user:
        dict_usernames[user.replace(".","_")] = "user_{}".format(user_md5hash[-6:])

print(dict_usernames)
content_list = sub_with_dict(dict_usernames, content_list)


is_json("".join(content_list))
output_json(json.dumps(json.loads("".join(content_list)), indent=3))

