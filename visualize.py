#!/usr/bin/env python3
import time
from datetime import datetime
import os
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from scipy.signal import savgol_filter
import dataset
	
def plot(db, stufftoplot, plotname, from_date = datetime(2000, 1, 1), to_date = datetime.now()):
	
	statement = f"SELECT timestamp FROM data WHERE timestamp BETWEEN DATETIME(:a) AND DATETIME(:b)"
	timestamps = db.query(statement, a=from_date, b=to_date)
	#timestamps = db[sGlobalGroup.name].find(timestamp={'between': [from_date, to_date]})
	x_axis = [datetime.strptime(v["timestamp"], "%Y-%m-%d %H:%M:%S.%f") for v in timestamps]
	
	y_axis = {}
	for stuff in stufftoplot:
		statement = f"SELECT {stuff} FROM data WHERE timestamp BETWEEN DATETIME(:a) AND DATETIME(:b)"
		data = db.query(statement, a=from_date, b=to_date)
		y_axis[stuff] = [v[stuff] for v in data]
	
	plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%d.%m.%Y %H:%M'))
	plt.gca().xaxis.set_major_locator(mdates.HourLocator(byhour = list(range(0,24,12))))
	
	# plotting the lines points  
	for stuff in stufftoplot:
	#	try:
	#		y_axis[stuff] = savgol_filter(y_axis[stuff], 15, 2)
	#	except:
	#		pass
		#plt.plot(x_axis, y_axis[stuff], label = f"{stuff.name} ({stuff.unit})")
		plt.plot(x_axis, y_axis[stuff], label = f"{stuff}")
		
	plt.gcf().autofmt_xdate()

	# naming the x axis 
	plt.xlabel("Time") 
	# naming the y axis 
	plt.ylabel('y - axis') 
	# giving a title to my graph 
	plt.title(plotname) 

	# show a legend on the plot 
	plt.legend() 

	# function to show the plot 
	plt.show() 

def main():
	
	db_url = f"sqlite:///log/stromverbrauch_{datetime.now().strftime('%Y_%m')}.db"
	#db_url = f"sqlite:///log/status_{datetime.now().strftime('%Y_11')}.db"
	from_date = datetime(2021, 10, 1)
	to_date = datetime.now()
	
	with dataset.connect(db_url) as db:
		plot(db, ["power"], "Power over time", from_date, to_date)
		plot(db, ["frequency"], "Frequency over time", from_date, to_date)
		plot(db, ["current_p1", "current_p2", "current_p3"], "Current over time", from_date, to_date)
		plot(db, ["voltage_p1", "voltage_p2", "voltage_p3"], "Voltage over time", from_date, to_date)
		plot(db, ["angle_i1_u1", "angle_i2_u2", "angle_i3_u3"], "Angle over time", from_date, to_date)

if __name__== "__main__":
	main() 

