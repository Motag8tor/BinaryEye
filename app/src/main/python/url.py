class URL:
    def __init__(self, id):
        self.ID = id
        self.harmless = 0
        self.malicious = 0
        self.suspicious = 0

    def set_harmless(self, value):
        print(value)
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
        if self.malicious >= 1:
            return "This URL appears to be malicious. It is recommended to avoid this website."
        if self.suspicious >= 1:
            return "This URL appears to be suspicious."
        return "This URL appears to be safe."