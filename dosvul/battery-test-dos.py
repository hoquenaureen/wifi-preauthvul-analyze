# Import dependencies and libraries.
from dependencies.libwifi.wifi import *
from dependencies.libwifi.crypto import rsn_prf_sha1, aes_wrap_key_withpad
from library.station import Authenticator

from scapy.contrib.wpa_eapol import WPA_key
from pbkdf2 import PBKDF2

battery = 100

class DenyProbeResponse(Authenticator):
    name = "ap-deny-probe-response"

    def handle_mon(self,p):
        global battery
        #If the packet received is a probe request, let's take a bit of battery off
        if p.subtype == 4:
            battery -= .1
            print("Probe Request Received, Battery Level: "+ str(battery))

    #Send this command to be interpreted by hostap
    def handle_started(self):
        self.wpaspy_command("SKIP_PROBE_RESPONSE 1")


    def handle_wpaspy(self, msg):
        if "Probe Request" in msg:
            log(DEBUG, "ap: "+msg)
            print("Probe Request Received")
 
class DenyAuthCommit(Authenticator):
    name = "ap-deny-auth-commit"

    def handle_mon(self,p):
        #print(scapy.layers.dot11.Dot11.mysummary(p))
        global battery
        if p.subtype == 4:
            battery -= .1
            print("Probe Request Received, Battery Level: "+ str(battery))
        if p.subtype == 11:
            battery -= .2
            print("Auth Packet Received, Battery Level: "+ str(battery))


    def handle_started(self):
        self.wpaspy_command("SKIP_AUTH_COMMIT 1")

    def handle_wpaspy(self, msg):
        if "Probe Request" in msg:
            log(DEBUG, "ap: "+msg)
        if "Commit" in msg:
            log(DEBUG, "ap: "+msg)
 

class DenyAuthConfirm(Authenticator):
    name = "ap-deny-auth-confirm"
    
    def handle_mon(self,p):
        #print(scapy.layers.dot11.Dot11.mysummary(p))
        global battery
        if p.subtype == 4:
            battery -= .1
            print("Probe Request Received, Battery Level: "+ str(battery))
        if p.subtype == 11:
            battery -= .2
            print("Auth Packet Received, Battery Level: "+ str(battery))


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

    def handle_mon(self,p):
        #print(scapy.layers.dot11.Dot11.mysummary(p))
        global battery
        if p.subtype == 4:
            battery -= .1
            print("Probe Request Received, Battery Level: "+ str(battery))
        if p.subtype == 11:
            battery -= .2
            print("Auth Packet Received, Battery Level: "+ str(battery))
        if p.subtype == 0:
            battery -= .2
            print("Association Packet Received, Battery Level: "+ str(battery))


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


    def handle_mon(self,p):
        #print(scapy.layers.dot11.Dot11.mysummary(p))
        global battery
        if p.subtype == 4:
            battery -= .1
            print("Probe Request Received, Battery Level: "+ str(battery))
        if p.subtype == 11:
            battery -= .2
            print("Auth Packet Received, Battery Level: "+ str(battery))
        if p.subtype == 0:
            battery -= .2
            print("Association Packet Received, Battery Level: "+ str(battery))

	def handle_started(self):
		# After hostap started, configure to skip the 4-way handshake
		# so we can handle it ourselves
		self.wpaspy_command("SKIP_4WAY 1")
		self.wpaspy_command("SKIP_MSG1 1")


							
	def handle_wpaspy(self, msg):
		"""Override the Station/Daemon-handler."""
		log(STATUS, "daemon: " + msg)



