class Wifi:
    def __init__(self):
        self.SSID = None
        self.password = None
        self.authentication = None
        self.hidden = False
        self.result = []

    def set_SSID(self, SSID):
        self.SSID = SSID

    def set_password(self, password):
        self.password = password

    def set_authentication(self, authentication):
        self.authentication = authentication

    def set_hidden(self):
        self.hidden = True

    def get_SSID(self):
        return self.SSID

    def get_report(self):
        self.result.append(self.SSID)

        if not self.password:
            self.result.append("nopass")

        if not self.authentication or self.authentication == "nopass":
            self.result.append("noauth")
        elif self.authentication == "WEP":
            self.result.append("authWEP")

        if self.hidden:
            self.result.append("hidden")
        
        return self.result