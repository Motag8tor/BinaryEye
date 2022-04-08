import validators, time, requests, re, apikey # Import external
import wifi, url, file # Import local
from io import BytesIO

apikey = apikey.apikey()
url_class = None
wifi_class = None
file_class = None

headers = {"Accept": "application/json", 
			"Content-Type": "application/x-www-form-urlencoded",
			"x-apikey": apikey}
			
# --------------------------------------------------------

def get_url_conclusion():
	global url_class
	return url_class.get_conclusion()

def get_url_downloadable():
	global url_class
	return url_class.get_downloadable()

def get_url_creation_date():
	global url_class
	return url_class.get_creation_date()

# --------------------------------------------------------

def get_url_analysis():
	global url_class
	if url_class: # Check if a url has been scanned
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
			url_class.get_report() # Generate report
			return "success" # Return successful message
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

def wifi_scanner():
	global wifi_class

	return wifi_class.get_report()

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

def get_file_analysis():
	global file_class
	if file_class: # Check if a file has been scanned
		id = file_class.get_ID()
		print(id)
	else:
		return 3 # If not then exit

	headers = {"Accept": "application/json",
				"x-apikey": apikey}

	VT_url = "https://www.virustotal.com/api/v3/files/" + id
	
	try:
		response = requests.request("GET", VT_url, headers=headers)
	except requests.ConnectTimeout as timeout:
		print(timeout)
		return 1

	if response:
		data = response.json()
		status = data["data"]["attributes"]["last_analysis_results"]
		#print(status)
		
		if status:
			print(data["data"]["attributes"]["last_analysis_stats"])
			file_class.set_harmless(data["data"]["attributes"]["last_analysis_stats"]["harmless"])
			file_class.set_malicious(data["data"]["attributes"]["last_analysis_stats"]["malicious"])
			file_class.set_suspicious(data["data"]["attributes"]["last_analysis_stats"]["suspicious"])
			return file_class.get_report() # Generate and return report
		elif not status:
			return 2
		else:
			return 3

# --------------------------------------------------------

def upload_file_for_scanning(contents):
	headers = {"x-apikey": apikey}

	VT_url = 'https://www.virustotal.com/api/v3/files'

	data_file = BytesIO(bytes(contents, "utf-8"))
	print(data_file.read())
	data_file.seek(0)
	files = {'file': ('file.exe', data_file)}

	try:
		response = requests.post(VT_url, headers=headers, files=files)
		print(response.text)
	except requests.ConnectTimeout as timeout:
		print(timeout)
		return "Unable to submit file for analysis. Please try again."

	if response:
		global file_class
		data = response.json()
		report_id = data["data"]["id"]
		file_class = file.File(report_id)
		return "file"

# --------------------------------------------------------

def analyser(qrcode):
	print("\n" + qrcode + "\n")
	data = qrcode.strip()

	valid_url = validators.url(data)
	if valid_url:
		global url_class
		print("URL Found...")
		url_class = None
		return upload_for_scanning(data)

	valid_wifi = re.search("^WIFI:((?:.+?:(?:[^\\;]|\\.)*;)+);?$", data)
	if valid_wifi:
		global wifi_class
		print("Wi-Fi Network Found...")
		wifi_class = None
		upload_wifi(data)
		return "wifi"

	if not valid_url or not valid_wifi:
		global file_class
		print("Generic file upload")
		file_class = None
		return upload_file_for_scanning(data)
	
	return 0

if __name__ == '__main__':
	upload_file_for_scanning("beans")