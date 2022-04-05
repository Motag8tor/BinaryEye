import requests, tldextract, whois, datetime

class URL:
    def __init__(self, id, address):
        self.ID = id
        self.address = address
        self.harmless = 0
        self.malicious = 0
        self.suspicious = 0

        self.domain = None
        self.headers = None
        self.creation_date = None
        self.conclusion = None
        self.downloadable = False

    def set_harmless(self, value):
        self.harmless = int(value)
    
    def set_malicious(self, value):
        self.malicious = int(value)
    
    def set_suspicious(self, value):
        self.suspicious = int(value)

# --------------------------------------------------------

    def get_ID(self):
        return self.ID

    def get_malicious(self):
        return self.malicious

    def get_conclusion(self):
        return self.conclusion

    def get_downloadable(self):
        return self.downloadable

    def get_creation_date(self):
        return self.creation_date

# --------------------------------------------------------

    def get_report(self):
        if self.address.startswith("ftp://"):
            self.downloadable = True
            print("FTP URL")
        elif self.address.startswith("sftp://"):
            self.downloadable = True
            print("SFTP URL")
        else:
            try:
                self.headers = requests.head(self.address).headers
            except:
                print("Unable to retrieve header.")
            
            if self.headers:
                if self.headers.get("Content-Disposition"):
                    print(self.headers.get("Content-Disposition"))
                    self.downloadable = "attachment" in self.headers.get("Content-Disposition")
                elif self.headers.get("Content-Type"):
                    print(self.headers.get("Content-Type"))
                    self.downloadable = "application/" in self.headers.get("Content-Type")
        print(self.downloadable)

        try:
            tld = tldextract.extract(self.address)
            self.domain = tld.registered_domain
        except:
            print("Unable to retrieve the top level domain.")
        print(self.domain)

        if self.domain:
            registered = None
            distance = None
            try:
                registered = whois.whois(self.domain)
            except:
                print("Unable to retrieve registration date")

            try:
                distance = datetime.datetime.now() - registered.creation_date[0]
            except:
                print()
            
            try:
                distance = datetime.datetime.now() - registered.creation_date
            except:
                print()

            if distance:
                self.creation_date = distance.days
                print(self.creation_date)
            else:
                self.creation_date = "0"

        if self.malicious >= 1:
            self.conclusion = "malicious"
        elif self.suspicious >= 1:
            self.conclusion = "suspicious"
        else:
            self.conclusion = "harmless"
        print(self.conclusion)