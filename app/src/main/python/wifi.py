class Wifi:
    def __init__(self):
        self.SSID = ""
        self.password = ""
        self.authentication = ""
        self.hidden = False

    def set_SSID(self, SSID):
        self.SSID = SSID

    def set_password(self, password):
        self.password = password

    def set_authentication(self, authentication):
        self.authentication = authentication

    def set_hidden(self):
        self.hidden = True

    def get_SSID(self):
        return
    
    def to_string(self):
        ssid_message = f'Analysis of the Wi-Fi network {self.SSID} shows:'
        pass_warning = None
        pass_message = None
        auth_warning = None
        auth_message = None

        if not self.password:
            pass_warning = "*WARNING* "
            pass_message = f'It does not require a password!'
        else:
            pass_message = f'It is password protected.'
        
        if not self.authentication or self.authentication == "nopass":
            auth_warning = "*WARNING* "
            auth_message = f'It does not use encryption!'
        elif self.authentication == "WEP":
            auth_warning = "*WARNING* "
            auth_message = f'It uses an outdated encryption standard!'
        else:
            auth_message = f'It uses {self.authentication} encryption.'

        hidden_message = f'It is not broadcasting its name.' if self.hidden else f'It is broadcasting its name.'

        recommendation = ""
        if pass_warning or auth_warning:
            recommendation = "It is advised that you do NOT join this network."

        return f'{ssid_message}\n{pass_warning}{pass_message}\n{auth_warning}{auth_message}\n{hidden_message}\n\n{recommendation}'