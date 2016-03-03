"""
Author: Logan Smithson
Date: July 2015
Description:
	Read in rules from Horizon in JSON format, convert to Snort format,
	and append to Snort rules file.
	Duplicate rules will not be written as determined by SIDs.

Assumptions:
	Snort .rules file exists, one rule per line, and lines beginning with '#' are to be ignored.
	Snort .rules file's ends with newline.
	JSON file is valid and of the form:

		[{"action": <str>, "protocol": <str>, "sourceip": <str>, "sourceport": <str>, "direction" : <str>, "destinationip": <str>,
			"destinationport": <str>, "msg": <str>, "priority" : <str>, "id" : <str>, "rev" : <str>}]

		E.g.

		[{"action": "alert", "protocol": "icmp", "sourceip": "192.168.1.1", "sourceport": "any", "direction" : "->", 
		"destinationip": "any", "destinationport": "any", "msg": "Test from script", "priority" : "10", "id" : "5000001", "rev" : "1"}]


TODO:
	* Implement snort process creation / restarting
	* Implement snort reloading
"""

# JSON_FILEPATH = "/opt/stack/horizon/openstack_dashboard/dashboards/mydashboard/rulespanel/rulesjason.json"
# RULES_FILEPATH = "/etc/snort/rules/local.rules"

# RULES_FILEPATH = "/etc/snort/rules/local.rules"
# JSON_FILEPATH = "/opt/stack/h-json/test.json"

RULES_FILEPATH = "test.rules"
JSON_FILEPATH = "test.json"


import json
import re


def main():
	jsonRules = loadJson(JSON_FILEPATH)
	sids = loadRuleSIDs(RULES_FILEPATH)
	jsonRules = removeDuplicateRules(jsonRules, sids)
	snortRules = jsonToSnort(jsonRules)
	writeRules(RULES_FILEPATH, snortRules)


def removeDuplicateRules(jsonRules, existingSIDs):
	"""
	Remove (ignore) the json rules that are already in the snort file
	"""
	for sid in existingSIDs:
		for jsonRule in jsonRules:
			if sid in jsonRule["sid"]:
				jsonRules.remove(jsonRule)

	return jsonRules


def jsonToSnort(jsonObject):
	"""
	Convert json formatted rules to Snort formatted rules
	"""
	snortRules = []

	for j in jsonObject:
		snortRule = "{0} {1} {2} {3} {4} {5} {6} (msg:{7}; priority:{8}; sid:{9};)".format(
								j['action'], j['protocol'], j['sourceip'], j['sourceport'], 
								j['direction'], j['destinationip'], j['destinationport'],
								j['msg'], j['priority'], j['sid'])

		snortRules.append(snortRule)
	return snortRules


def loadJson(infile):
	"""
	Open JSON file and return object containing JSON data.
	"""
	with open(infile) as jsonFile:
		jsonData = json.load(jsonFile)

	return jsonData


def loadRuleSIDs(infile):
	"""
	Assuming one rule per line, get all SIDs of valid existing snort rules.
	Blank lines and comment (#) lines are ignored.
	"""
	sids = []
	lineNumber = 1

	#with open(infile, encoding="utf8") as rulesFile:  # encoding errors; change to utf8
	with open(infile) as rulesFile: 
		for line in rulesFile:
			if not line.strip().startswith('#') and not line.strip() == "":  # ignore blank and comment lines
				try:  # find the sid in each rule; case insinsitive
					match = re.search(r'sid:(?P<sid>\d+)', line, re.I)
					sids.append(match.group('sid'))
				except AttributeError as e:  # if the sid isn't found/doesn't exist
					print("No sid on line " + str(lineNumber))
			lineNumber += 1

	return sids


def writeRules(outfile, rules):
	"""
	Append Snort rules to outfile.
	"""
	with open(outfile, 'a') as ofile:
		for rule in rules:
			ofile.write(rule + '\n')


if __name__ == "__main__":
	main()
