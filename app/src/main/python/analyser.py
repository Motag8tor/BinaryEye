import cv2 # Image reading library
import sys, os, validators, time, requests, re

from dotenv import load_dotenv
load_dotenv()

def get_analysis(id, headers):
	status = {}
	retries = 3
	
	url = "https://www.virustotal.com/api/v3/analyses/" + id
	
	while retries > 0:
		try:
			response = requests.request("GET", url, headers=headers)
		except requests.ConnectTimeout as timeout:
			print("Connection timed out.")
			print(timeout)
			
		if response:
			data = response.json()
			status = data["data"]["attributes"]["status"]
			
			if status == "completed":
				print(data["data"]["attributes"]["stats"])
				break
			elif status == "queued":
				print("Report is not ready yet. Retrying...")
				time.sleep(7)
			else:
				print("There was an error with the request. Aborting...")
				break
				
		retries -= 1
	if retries <= 0:
		print("Unable to retrieve report. Aborting...")
	
# --------------------------------------------------------

def upload_for_scanning(payload, headers):
	print("\n-------------------------\n")
	url = "https://www.virustotal.com/api/v3/urls"

	try:
		response = requests.request("POST", url, data="url=" + payload, headers=headers)
	except requests.ConnectTimeout as timeout:
		print("Connection timed out.")
		print(timeout)
		
	if response:
		data = response.json()
		report_id = data["data"]["id"]
		get_analysis(report_id, headers)

# --------------------------------------------------------

def analyser(image):
	qrcode = image
	print("\n" + qrcode + "\n")

	# Print data
	headers = {
		"Accept": "application/json",
		"Content-Type": "application/x-www-form-urlencoded"
	}
	headers["x-apikey"] = "681da8da48f79afcced8b6077cb3d05ff84ad3f66815084910c69505a620b783"
	print(headers["x-apikey"])

	message = qrcode + " contains "
	data = qrcode.strip()
	try:
		int(data)
		valid_int = True
	except ValueError as e:
		valid_int = False

	valid_wifi = re.search("WIFI:T:.*;S:.*;P:.*;;", data)

	valid_url = validators.url(data)

	if valid_url:
		print(message + "URL. Validating URL...")
		upload_for_scanning(data, headers)
	elif valid_int:
		print(message + "numbers: " + data)
	elif valid_wifi:
		wifi_name = re.search(";S:.*;P:", data)
		print(message + "a Wi-Fi connection named: " + wifi_name[0].strip(";S:").strip(";P:"))
	else:
		print(message + "message: " + data)