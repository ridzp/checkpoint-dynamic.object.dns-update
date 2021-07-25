import json
import socket
with open("C:/Python27/dyn_obj.json") as file:
    data = json.load(file)
    #print(data["client"]["name"])
    #data["client"]["name"] = "Riddhiman Phukon"

#    data["dynobj"][0]["dig_new"][0] = "5.5.5.5"
#    data["dynobj"][0]["dig_new"][1] = "6.6.6.6"
#    data["dynobj"][0]["dig_new"][2] = "7.7.7.7"
y = range(len(data["dynobj"]))
for x in y:
    dns_resolve = socket.gethostbyname_ex(data["dynobj"][x]["hostname"])
    ip_addresses = range(len(dns_resolve[2]))
    data["dynobj"][x]["dig_new"].clear()
    for i in ip_addresses:
        data["dynobj"][x]["dig_new"].append(dns_resolve[2][i])

with open("C:/Python27/dyn_obj.json", 'w') as file:
    json.dump(data, file, indent = 4)

#-------------------------------completed testing on python ver 2.7
#--- DNS resolution done and updated dig_new
#--------------------------------
#----  search for objects associated with each firewall hostnames

with open("C:/Python27/firewalls.json") as fw_file:
    fw_data = json.load(fw_file)
object_selector = []
u = range(len(fw_data["firewalls"]))
n = range(len(data["dynobj"]))
for v in u:
    for m in n:
        if fw_data["firewalls"][v]["fw_hostname"] in data["dynobj"][m]["fw_hostnames"]:
            object_selector.append(data["dynobj"][m]["object_name"])

    for dyn_objects in object_selector:
        for ex in y:
            if dyn_objects in data["dynobj"][ex]["object_name"]:
                dignew_set = set(data["dynobj"][ex]["dig_new"])
                digold_set = set(data["dynobj"][ex]["dig_old"])
                if(dignew_set != digold_set):
                    ip_add = dignew_set.difference(digold_set)
                    ip_remove = digold_set.difference(dignew_set)
                    if len(ip_add) != 0:
                        print ("Dynmic Object =", data["dynobj"][ex]["object_name"], " firewall = ", fw_data["firewalls"][v]["fw_hostname"])
                        for ax in ip_add:
                            print ("IP to be added" , ax)

                    if len(ip_remove) != 0:
                        print ("Dynmic Object =", data["dynobj"][ex]["object_name"], " firewall = ", fw_data["firewalls"][v]["fw_hostname"])
                        for rx in ip_remove:
                            print ("IP to be removed" , rx)
    object_selector.clear()








