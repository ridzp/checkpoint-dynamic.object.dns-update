import json
import socket
import time
import paramiko

ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
flag = 0

with open("C:/Python27/dyn_obj.json") as file:
    data = json.load(file)


y = range(len(data["dynobj"]))
for x in y:
    dns_resolve = socket.gethostbyname_ex(data["dynobj"][x]["hostname"])
    ip_addresses = range(len(dns_resolve[2]))
    data["dynobj"][x]["dig_new"].clear()
    for i in ip_addresses:
        data["dynobj"][x]["dig_new"].append(dns_resolve[2][i])

#with open("C:/Python27/dyn_obj.json", 'w') as file:
    #json.dump(data, file, indent = 4)

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

                    if flag == 0:
                        #ssh_client.get_transport().is_active
                        ssh_client.connect(hostname= fw_data["firewalls"][v]["fw_ip_address"], port=22, username='admin', password=fw_data["firewalls"][v]["fw_password"],look_for_keys=False, allow_agent=False)
                        flag = 1
                        shell = ssh_client.invoke_shell()
                        time.sleep(2)
                        shell.send('expert\n')
                        time.sleep(2)
#                       shell.send(fw_data["firewalls"][v]["fw_password"]+'\n')
                        shell.send('qaz123\n')
                        time.sleep(2)
                        shell.send('vsenv 1\n')
                        time.sleep(2)

                        print(ssh_client.get_transport().is_active())
                        output = shell.recv(10000)
                        output = output.decode('utf-8')
                        print(output)
                    if len(ip_add) != 0:
                        print ("Dynmic Object =", data["dynobj"][ex]["object_name"], " firewall = ", fw_data["firewalls"][v]["fw_hostname"])
                        for ax in ip_add:
                            print ("IP to be added" , ax)
                            shell.send('dynamic_objects -o ' + data["dynobj"][ex]["object_name"] + ' -r ' + ax + ' ' + ax + ' -a\n')
                            time.sleep(1)
                            print('dynamic_objects -o ' + data["dynobj"][ex]["object_name"] + ' -r ' + ax + ' ' + ax + ' -a\n')
                            output = shell.recv(10000)
                            output = output.decode('utf-8')
                            print(output)

                    if len(ip_remove) != 0:
                        print ("Dynmic Object =", data["dynobj"][ex]["object_name"], " firewall = ", fw_data["firewalls"][v]["fw_hostname"])
                        for rx in ip_remove:
                            print ("IP to be removed" , rx)
                            shell.send('dynamic_objects -o ' + data["dynobj"][ex]["object_name"] + ' -r ' + rx + ' ' + rx + ' -d\n')
                            time.sleep(1)
                            print('dynamic_objects -o ' + data["dynobj"][ex]["object_name"] + ' -r ' + rx + ' ' + rx + ' -d\n')
                            output = shell.recv(10000)
                            output = output.decode('utf-8')
                            print(output)
    object_selector.clear()
    ssh_client.close()
    flag = 0

#replaced old dig result IP address with the new dig result
for bx in y:
    data["dynobj"][bx]["dig_old"].clear()
    data["dynobj"][bx]["dig_old"] = data["dynobj"][bx]["dig_new"]

#updated dynamic object json file
with open("C:/Python27/dyn_obj.json", 'w') as file:
    json.dump(data, file, indent = 4)





