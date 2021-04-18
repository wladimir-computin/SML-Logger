#!/usr/bin/env python3
from cryptoiot import *
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

	
descriptions = {"1-0:1.8.0/255":"total_consumption",
				"1-0:16.7.0/255":"power",
				"1-0:32.7.0/255":"voltage_p1",
				"1-0:52.7.0/255":"voltage_p2",
				"1-0:72.7.0/255":"voltage_p3",
				"1-0:31.7.0/255":"current_p1",
				"1-0:51.7.0/255":"current_p2",
				"1-0:71.7.0/255":"current_p3",
				"1-0:81.7.1/255":"angle_p1",
				"1-0:81.7.2/255":"angle_p2",
				"1-0:81.7.4/255":"angle_p3",
				#"1-0:81.7.15/255":"phase_angle_u2_i2",
				#"1-0:81.7.26/255":"phase_angle_u3_i3"
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
	
	def start(self):
		self.now = None
		
	def loop(self):
		sml_json = self.cc.send("parsedsml").replace("DATA::", "")
		
		jsn = json.loads(sml_json)
		jsn = add_name(jsn)
		
		data = {}
		desc = {}
		
		for element in jsn:
			data[element["name"]] = element["val"]
		
		try:
			now = datetime.now().replace(microsecond=0)
			if self.now is None or self.now.month != now.month:
				self.db = dataset.connect(f"sqlite:///log/stromverbrauch_{now.strftime('%Y_%m')}.db")
			self.now = now
			self.db.begin()
			ins = {}
			ins.update({"timestamp" : self.now})
			ins.update(data)
			self.db["data"].insert(ins)
			self.db.commit()
		except Exception as x:
			print(x)
			self.db.rollback()
			#json.dump(groups, f, indent=4)
		
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
