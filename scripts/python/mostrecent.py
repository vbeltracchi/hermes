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
                	l.write(t + ' - mostrecent.py - Connected to Snort DB\n')
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
	# query = ("select sid,cid,signature,CAST(timestamp as CHAR) as timestamp from event order by sid desc limit 10")
	#query=("select ip_ver,count(*) from iphdr group by ip_ver")
	query = ("select cid,inet_ntoa(ip_src) as ip_src from iphdr order by cid desc limit 10")
	# Execute the query
	cur.execute(query)
	
	# Put the records from DB into the dictionary
	
	query_result = [ dict(line) for line in [zip([ column[0] for column in cur.description], row) for row in cur.fetchall()] ]

	event_json = json.dumps(query_result, indent=4)

	json_file = '/opt/stack/h-json/mostrecent.json'

	f = open(json_file, 'w')
	print >> f, event_json
	
	# Close all
	cur.close()
	dbc.close()
	f.close()

if __name__ == "__main__":
    main(sys.argv)

