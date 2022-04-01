import validators, time, requests, re, apikey, wifi, url

apikey = apikey.apikey()
url_class = None
wifi_class = None

headers = {"Accept": "application/json", 
			   "Content-Type": "application/x-www-form-urlencoded",
			   "x-apikey": apikey}

def get_url_analysis():
	global url_class
	if url_class: # Check if an url has been scanned
		id = url_class.get_ID()
		print(id)
	else:
		return 3 # If not then exit

	VT_url = "https://www.virustotal.com/api/v3/analyses/" + id
	
	try:
		response = requests.request("GET", VT_url, headers=headers)
	except requests.ConnectTimeout as timeout:
		print(timeout)
		return 1

	if response:
		data = response.json()
		status = data["data"]["attributes"]["status"]
		
		if status == "completed":
			print(data["data"]["attributes"]["stats"])
			url_class.set_harmless(data["data"]["attributes"]["stats"]["harmless"])
			url_class.set_malicious(data["data"]["attributes"]["stats"]["malicious"])
			url_class.set_suspicious(data["data"]["attributes"]["stats"]["suspicious"])
			return url_class.get_report()
		elif status == "queued":
			return 2
		else:
			return 3
	
# --------------------------------------------------------

def upload_for_scanning(address):
	VT_url = "https://www.virustotal.com/api/v3/urls"

	try:
		response = requests.request("POST", VT_url, data="url=" + address, headers=headers)
	except requests.ConnectTimeout as timeout:
		print(timeout)
		return "Unable to submit URL for analysis. Please try again."
		
	if response:
		global url_class
		data = response.json()
		report_id = data["data"]["id"]
		url_class = url.URL(report_id, address)
		return "url"

# --------------------------------------------------------

def upload_wifi(data):
	global wifi_class
	wifi_class = wifi.Wifi()

	array = re.findall("(.+?):((?:[^\\;]|\\.)*);", data[5:])
	print(array)

	for i in array:
		if i[0] == "S":
			wifi_class.set_SSID(i[1])
		elif i[0] == "T":
			wifi_class.set_authentication(i[1])
		elif i[0] == "P":
			wifi_class.set_password(i[1])
		elif i[0] == "H":
			wifi_class.set_hidden()

	return wifi_scanner()

# --------------------------------------------------------

def wifi_scanner():
	global wifi_class

	return wifi_class.get_report()

# --------------------------------------------------------

def get_wifi_class():
	global wifi_class
	return wifi_class

def analyser(qrcode):
	print("\n" + qrcode + "\n")
	data = qrcode.strip()

	valid_url = validators.url(data)
	if valid_url:
		print("URL Found...")
		url_class = None
		return upload_for_scanning(data)

	valid_wifi = re.search("^WIFI:((?:.+?:(?:[^\\;]|\\.)*;)+);?$", data)
	if valid_wifi:
		print("Wi-Fi Network Found...")
		wifi_class = None
		upload_wifi(data)
		return "wifi"
	
	return 0