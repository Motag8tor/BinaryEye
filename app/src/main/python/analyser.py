import validators, time, requests, re, apikey, wifi

apikey = apikey.apikey()

def get_analysis(id, headers):
	retries = 3
	
	url = "https://www.virustotal.com/api/v3/analyses/" + id
	
	while retries > 0:
		try:
			response = requests.request("GET", url, headers=headers)
		except requests.ConnectTimeout as timeout:
			print(timeout)
			return "Unable to retrieve URL analysis report. Please try again."
			
		if response:
			data = response.json()
			status = data["data"]["attributes"]["status"]
			
			if status == "completed":
				return data["data"]["attributes"]["stats"]
			elif status == "queued":
				print("Report is not ready yet. Retrying...")
				time.sleep(7)
			else:
				print("There was an error with the request. Aborting...")
				break
				
		retries -= 1
	if retries <= 0:
		print("Unable to retrieve report. Aborting...")
		return "The report took too long to process. Please try again."
	
# --------------------------------------------------------

def upload_for_scanning(payload):
	headers = {"Accept": "application/json", 
			   "Content-Type": "application/x-www-form-urlencoded",
			   "x-apikey": apikey}

	url = "https://www.virustotal.com/api/v3/urls"

	try:
		response = requests.request("POST", url, data="url=" + payload, headers=headers)
	except requests.ConnectTimeout as timeout:
		print(timeout)
		return "Unable to submit URL for analysis. Please try again."
		
	if response:
		data = response.json()
		report_id = data["data"]["id"]
		return get_analysis(report_id, headers)

# --------------------------------------------------------

def wifi_scanner(data):
	array = re.findall("(.+?):((?:[^\\;]|\\.)*);", data[5:])
	print(array)

	wifi_class = wifi.Wifi()

	for i in array:
		print(i[0])
		if i[0] == "S":
			wifi_class.set_SSID(i[1])
		elif i[0] == "T":
			wifi_class.set_authentication(i[1])
		elif i[0] == "P":
			wifi_class.set_password(i[1])
		elif i[0] == "H":
			wifi_class.set_hidden()

	return wifi_class.to_string()

# --------------------------------------------------------

def analyser(qrcode):
	print("\n" + qrcode + "\n")

	data = qrcode.strip()

	valid_url = validators.url(data)
	if valid_url:
		print("Validating URL...")
		return upload_for_scanning(data)

	valid_wifi = re.search("^WIFI:((?:.+?:(?:[^\\;]|\\.)*;)+);?$", data)
	if valid_wifi:
		print("Validating Wi-Fi...")
		return wifi_scanner(data)