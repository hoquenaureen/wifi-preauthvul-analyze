# Import dependencies and libraries.
from dependencies.libwifi.wifi import *
from dependencies.libwifi.crypto import rsn_prf_sha1, aes_wrap_key_withpad
from library.station import Authenticator

from scapy.contrib.wpa_eapol import WPA_key
from pbkdf2 import PBKDF2


class DenyProbeResponse(Authenticator):
    name = "ap-deny-probe-response"

    #Send this command to be interpreted by hostap
    def handle_started(self):
        self.wpaspy_command("SKIP_PROBE_RESPONSE 1")


    def handle_wpaspy(self, msg):
        if "Probe Request" in msg:
            log(DEBUG, "ap: "+msg)
 
class DenyAuthCommit(Authenticator):
    name = "ap-deny-auth-commit"

    def handle_started(self):
        self.wpaspy_command("SKIP_AUTH_COMMIT 1")


    def handle_wpaspy(self, msg):
        if "Probe Request" in msg:
            log(DEBUG, "ap: "+msg)
        if "Commit" in msg:
            log(DEBUG, "ap: "+msg)
 

class DenyAuthConfirm(Authenticator):
    name = "ap-deny-auth-confirm"
    
    def handle_started(self):
        self.wpaspy_command("SKIP_AUTH_CONFIRM 1")


    def handle_wpaspy(self, msg):
        if "Probe Request" in msg:
            log(DEBUG, "ap: "+msg)
        if "Commit" in msg:
            log(DEBUG, "ap: "+msg)
        if "Confirm" in msg:
            log(DEBUG, "ap: "+msg)

class DenyAssoc(Authenticator):
    name = "ap-deny-assoc-resp"

    def handle_started(self):
        self.wpaspy_command("SKIP_ASSOC_RESP 1")


    def handle_wpaspy(self, msg):
        if "Probe Request" in msg:
            log(DEBUG, "ap: "+msg)
        if "Commit" in msg:
            log(DEBUG, "ap: "+msg)
        if "Confirm" in msg:
            log(DEBUG, "ap: "+msg)
        if "Association Response" in msg:
            log(DEBUG, "ap: "+msg)
 


class DenyMsg1(Authenticator):
	"""Authenticator Station."""
	name = "ap-deny-msg1"


	def handle_started(self):
		# After hostap started, configure to skip the 4-way handshake
		# so we can handle it ourselves
		self.wpaspy_command("SKIP_4WAY 1")
		self.wpaspy_command("SKIP_MSG1 1")


							
	def handle_wpaspy(self, msg):
		"""Override the Station/Daemon-handler."""
		log(STATUS, "daemon: " + msg)



