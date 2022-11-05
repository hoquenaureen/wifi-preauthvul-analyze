## Systematically Analyzing Vulnerabilities in the Connection Establishment Phase of Wi-Fi Systems

N. Hoque, H. Rahbari, and C. Rezendes, “Systematically analyzing vulnerabilities in the connection establishment phase of Wi-Fi systems,” in Proceedings of IEEE Conference on Communications and Network Security (CNS), Austin, Texas, Oct. 2022.


To establish a secure Wi-Fi connection, several unprotected management frames are exchanged between an access point and a station before they mutually authenticate each other and start a protected session. In this paper, we are the first to formally model and analyze this connection establishment phase, based on the latest IEEE 802.11 standard, and accordingly, expose a new denial of service (DoS) vulnerability and three new variants of a known man-in-the-middle (MitM) attack. We also formally show that the optional operating channel validation technique introduced in the latest standard is capable of protecting the system only against multi-channel MitM. To validate our identified DoS vulnerability, we test it against the latest *wpa supplicant* daemon, showing that an adversary can stealthily prevent a station from connecting to a preferred AP for up to $90$ minutes, likely more. We also propose a mitigation approach to counter it. 

Formal analysis:    https://github.com/hoquenaureen/wifi-preauthvul-analyze/tree/main/mc

Validation testbed: https://github.com/hoquenaureen/wifi-preauthvul-analyze/tree/main/dosvul
