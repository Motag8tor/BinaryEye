import requests

class URL:
    def __init__(self, id, address):
        self.ID = id
        self.address = address
        self.harmless = 0
        self.malicious = 0
        self.suspicious = 0
        self.result = []

    def set_harmless(self, value):
        self.harmless = int(value)
    
    def set_malicious(self, value):
        self.malicious = int(value)
    
    def set_suspicious(self, value):
        self.suspicious = int(value)

    def get_ID(self):
        return self.ID

    def get_malicious(self):
        return self.malicious

    def get_report(self):
        downloadable = False
        if self.address.startswith("ftp://"):
            downloadable = True
        else:
            headers = requests.head(self.address).headers
            print(headers.get("Content-Type"))
            print(headers.get("Content-Disposition"))
            downloadable = "application/" in headers.get("Content-Type") or "attachment" in headers.get("Content-Disposition")

        if downloadable:
            self.result.append("downloadable")
        print(downloadable)

        if self.malicious >= 1:
            self.result.append("malicious")
        elif self.suspicious >= 1:
            self.result.append("suspicious")
        else:
            self.result.append("harmless")
        return self.result