import validators, time, requests, re

def get_analysis(id, headers):
	retries = 3
	
	url = "https://www.virustotal.com/api/v3/analyses/" + id
	
	while retries > 0:
		try:
			response = requests.request("GET", url, headers=headers)
		except requests.ConnectTimeout as timeout:
			print(timeout)
			return "Connection timed out."
			
		if response:
			data = response.json()
			status = data["data"]["attributes"]["status"]
			
			if status == "completed":
				return data["data"]["attributes"]["stats"]
				break
			elif status == "queued":
				print("Report is not ready yet. Retrying...")
				time.sleep(7)
			else:
				print("There was an error with the request. Aborting...")
				break
				
		retries -= 1
	if retries <= 0:
		return "Unable to retrieve report. Aborting..."
	
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
		return get_analysis(report_id, headers)

# --------------------------------------------------------

def analyser(qrcode, apikey):
	print("\n" + qrcode + "\n")

	# Print data
	headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
			   "x-apikey": apikey}

	message = "QRCode contains "
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
		return upload_for_scanning(data, headers)
	elif valid_int:
		print(message + "numbers: " + data)
	elif valid_wifi:
		wifi_name = re.search(";S:.*;P:", data)
		print(message + "a Wi-Fi connection named: " + wifi_name[0].strip(";S:").strip(";P:"))
	else:
		print(message + "message: " + data)