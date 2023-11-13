import hashlib
import requests
import os
import sys
import threading
import time
import json


sha256 = hashlib.sha256()
if sys.argv[1]:
	file = os.path.abspath(sys.argv[1])
else:
	print("No input file provided");
	exit(1)
if not os.path.exists(file):
	print("No input file found at path");
	exit(1)

if not sys.argv[2]:
	print("No key provided");
	exit(1)

with open(file,"rb") as f:
        content = f.read()
        hash = hashlib.sha256(content).hexdigest()

print(hash)

def printResults(response):
	print(response.text)
	print("printResults " + json.dumps(response.json(), indent = 4))
	data = response.json();
	details = data["scan_results"]["scan_details"]
	if details:
		print("Filename " + sys.argv[1]) 
		print("OverallStatus " + data["scan_results"]["scan_all_result_a"]) 
		for engine in details.keys():
			print("Engine " + engine) 
			engineDetails = details[engine]
			print("ThreatFound " + engineDetails["threat_found"]) 
			print("ScanResults " + str(engineDetails["scan_result_i"]))
			print("DateTime " + engineDetails["def_time"])
	else:
		print("No details in response")

def thread_function(data_id):
	while True:
		url = "https://api.metadefender.com/v4/file/" + data_id
		headers = {
			"apikey": sys.argv[2],
			"x-file-metadata": "1"
				}
		response = requests.request("GET", url, headers=headers)
		responseData = response.json()
		print("Threading " + json.dumps(response.json(), indent = 4))
		if(responseData['scan_results']['progress_percentage'] == 100):
			printResults(response)
			break;
		else:
			time.sleep(10)

url = "https://api.metadefender.com/v4/hash/" + hash
headers = {"apikey": sys.argv[2]}

response = requests.request("GET", url, headers=headers)

print(response.text)

if response.status_code == 404:
	url = "https://api.metadefender.com/v4/file"
	headers = {
		"apikey": sys.argv[2],
		"filename": sys.argv[1],
			  }
	  
	files = {"file": open(file, 'rb')}
	response = requests.request("POST", url, headers=headers, files=files)
	
	print(response.text)	
	responseData = response.json()
	data_id = responseData["data_id"]
	
	t = threading.Thread(target=thread_function, args=(data_id,))
	t.start();
	t.join();

else:
	printResults(response)
	