import pathlib


class SIOconfiguration:
    def __init__(self):
        self.admin_username = 'admin'
        self.admin_password = 'Scaleio123'
        self.user_session_hard_timeout_secs = 2592000
        self.user_session_timeout_secs = 2592000
        self.data_A_mask = '192.168.'
        self.data_B_mask = '172.17.'
        self.server_user = 'root'
        self.server_password = 'password'


class Integration:
    def __init__(self):
        self.log_location = pathlib.Path(__file__).parent

