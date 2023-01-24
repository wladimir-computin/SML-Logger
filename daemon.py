#!/usr/bin/env python3
from ciotclient2 import *
from datetime import datetime
import time
import signal
import json
from json import JSONEncoder
import os
import dataset

def _default(self, obj):
    return getattr(obj.__class__, "__json__", _default.default)(obj)

_default.default = JSONEncoder().default
JSONEncoder.default = _default 

#######################################

logger = None

RETRYS = 4

	
descriptions = {"1-0:1.8.0/255":"total_consumption",
				"1-0:16.7.0/255":"power",
				"1-0:32.7.0/255":"voltage_p1",
				"1-0:52.7.0/255":"voltage_p2",
				"1-0:72.7.0/255":"voltage_p3",
				"1-0:31.7.0/255":"current_p1",
				"1-0:51.7.0/255":"current_p2",
				"1-0:71.7.0/255":"current_p3",
				"1-0:81.7.1/255":"angle_u2_u1",
				"1-0:81.7.2/255":"angle_u3_u1",
				"1-0:81.7.4/255":"angle_i1_u1",
				"1-0:81.7.15/255":"angle_i2_u2",
				"1-0:81.7.26/255":"angle_i3_u3",
				"1-0:14.7.0/255":"frequency"}

def add_name(jsn):
	out = []
	for element in jsn:
		if element["id"] in descriptions.keys():
			element["name"] = descriptions[element["id"]]
			out.append(element)
	return out
			

class Logger:
	
	def __init__(self, ip, port, devicepass):
		transport = Transport_UDP(ip, port)
		self.cc = CryptCon(transport, devicepass)
		self.current_db_path = None
		self.db = None
	
	def start(self):
		pass
		
	def loop(self):
		print("Retrieving SML")
		sml_json = ""
		for i in range(RETRYS):
			sml_json = self.cc.send("SML:parsedsml")
			if sml_json is not None and sml_json != "D::[]":
				sml_json = sml_json.replace("D:", "")
				break
			else:
				print("Trying again")
				time.sleep(2)
			
		if sml_json is not None and sml_json != "":
			print(sml_json)
			jsn = json.loads(sml_json)
			jsn = add_name(jsn)

			print(json.dumps(jsn, indent=4))
			
			data = {}
			desc = {}
			
			for element in jsn:
				data[element["name"]] = element["val"]
			
			self.now = datetime.now().replace(microsecond=0)
			ins = {}
			ins.update({"timestamp" : self.now})
			ins.update(data)
			
			db_path = f"sqlite:///log/stromverbrauch_{self.now.strftime('%Y_%m')}.db"
			if self.db is None or self.current_db_path != db_path:
				self.db = dataset.connect(db_path, sqlite_wal_mode=False)
				self.current_db_path = db_path
			
			self.db["data"].insert(ins)
		
	def end(self):
		pass
		#self.cc.close()

def main():
	with open('config.json') as config_file:
		config = json.load(config_file)
		signal.signal(signal.SIGINT, handler)
		
		global logger
		logger = Logger(config["ip"], config["port"], config["devicepass"])
		logger.start()
		while True:
			try:
				logger.loop()
				time.sleep(60 - time.localtime().tm_sec)
			except Exception as e:
				print(e)
				time.sleep(5)
	
def handler(signum, frame):
	exit()

def exit():
	global logger
	logger.end()
	quit()

if __name__== "__main__":
	main() 
