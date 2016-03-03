#    Vittorio Beltracchi
#    July 2015
#    Version: 0.5

import sys
import json
import mysql.connector
from mysql.connector import Error
import datetime

def db_connect():
	""" Connection to the IDS database and logging """
	# Definte TimeStamp
	t = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')
	# Define logfile
        hermes_log = 'h-script.log'
        try:
                l = open(hermes_log,'a')
        except IOError as e:
                print(e)

	try:
		cnx = mysql.connector.connect(user='root', password='password', database='snort')
		if cnx.is_connected():
                	l.write(t + ' - sampevents.py - Connected to Snort DB\n')
			l.close()
			return cnx
	except Error as e:
        	l.write(t + ' ' + e + '\n')
		l.close()
		#print(e)

def main(argv):
	""" Main of the script """
	# Get the DB connection
	dbc = db_connect()

	# Set the cursor
	cur = dbc.cursor()
	
	# Define the query put it into tuple ()
	#query = ("select * from event")
	#query=("select ip_ver,count(*) from iphdr group by ip_ver")
	query = ("select sid,cid,signature,CAST(timestamp as char) as timestamp from event")
	# Execute the query
	cur.execute(query)
	
	# Put the query result into an iterable object
	#rows = cur.fetchall()
	
	# List to contain the events
	#event_list = []

	# Dictionary to contain the JSON attributes
	# dic = dict()
	
	# Counter for Unique ID needed in this case
	# i = 0
	
	# Get the names of columns
	#columns = [desc[0] for desc in cur.description]
	
	query_result = [ dict(line) for line in [zip([ column[0] for column in 
                     cur.description], row) for row in cur.fetchall()] ]
    	#print query_result
	# Put the records from DB into the dictionary
	#for row in rows:
		# print(record))
       		# dic['sid'] = record[0]
        	# dic['cid'] = record[1]
        	# dic['signature'] = record[2]
        	# dic['timestamp'] = str(record[3])
		# dic['id'] = i
		# row = dict(zip(columns,str(row)))	
		# Increase the counter
		# i += 1	
		
		# r = (str(row.sid), str(row.cid), str(row.signature), str(row.timestamp))
		# print(row)
		# Append the record to the list	
		#event_list.append(r)

	event_json = json.dumps(query_result, indent=4)

	json_file = '/opt/stack/h-json/sampevents.json'

	f = open(json_file, 'w')
	print >> f, event_json
	
	# Close all
	cur.close()
	dbc.close()
	f.close()

if __name__ == "__main__":
    main(sys.argv)

