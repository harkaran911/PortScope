"""Well-known port → service/risk database."""

PORT_SERVICE_MAP = {
    21:   {"service": "FTP",        "risk": "high",     "notes": "File Transfer Protocol — often allows anonymous login; plaintext credentials"},
    22:   {"service": "SSH",        "risk": "medium",   "notes": "Secure Shell — brute-force target; check for weak auth"},
    23:   {"service": "Telnet",     "risk": "critical", "notes": "Telnet — plaintext protocol; replace with SSH immediately"},
    25:   {"service": "SMTP",       "risk": "medium",   "notes": "Mail Transfer — can be abused for spam relay if open to all"},
    53:   {"service": "DNS",        "risk": "medium",   "notes": "Domain Name System — check for zone transfer vulnerability"},
    67:   {"service": "DHCP",       "risk": "medium",   "notes": "DHCP Server — rogue DHCP risk on LAN"},
    68:   {"service": "DHCP",       "risk": "low",      "notes": "DHCP Client"},
    69:   {"service": "TFTP",       "risk": "high",     "notes": "Trivial FTP — no authentication; data exposure risk"},
    80:   {"service": "HTTP",       "risk": "medium",   "notes": "Web Server — check for default pages, information disclosure"},
    110:  {"service": "POP3",       "risk": "medium",   "notes": "POP3 Mail — plaintext credentials if not encrypted"},
    111:  {"service": "RPC",        "risk": "high",     "notes": "Sun RPC portmapper — information disclosure and exploit surface"},
    119:  {"service": "NNTP",       "risk": "low",      "notes": "Network News Transfer"},
    123:  {"service": "NTP",        "risk": "medium",   "notes": "NTP — amplification DDoS vector if misconfigured"},
    135:  {"service": "MSRPC",      "risk": "high",     "notes": "Microsoft RPC — common attack surface on Windows"},
    137:  {"service": "NetBIOS-NS", "risk": "high",     "notes": "NetBIOS Name Service — information disclosure"},
    138:  {"service": "NetBIOS-DG", "risk": "high",     "notes": "NetBIOS Datagram — Windows file sharing vector"},
    139:  {"service": "NetBIOS-SS", "risk": "critical", "notes": "NetBIOS Session Service — SMB over NetBIOS; EternalBlue risk"},
    143:  {"service": "IMAP",       "risk": "medium",   "notes": "IMAP Mail — check for plaintext auth"},
    161:  {"service": "SNMP",       "risk": "high",     "notes": "SNMP — default community strings expose device info"},
    162:  {"service": "SNMP-Trap",  "risk": "medium",   "notes": "SNMP Trap receiver"},
    179:  {"service": "BGP",        "risk": "critical", "notes": "Border Gateway Protocol — routing infrastructure exposure"},
    389:  {"service": "LDAP",       "risk": "high",     "notes": "Directory Service — anonymous bind may expose user data"},
    443:  {"service": "HTTPS",      "risk": "low",      "notes": "Encrypted Web — check TLS version and certificate"},
    445:  {"service": "SMB",        "risk": "critical", "notes": "SMB — EternalBlue/WannaCry; ensure patched and firewalled"},
    465:  {"service": "SMTPS",      "risk": "low",      "notes": "SMTP over SSL"},
    500:  {"service": "IKE/IPSec",  "risk": "medium",   "notes": "VPN key exchange — aggressive mode fingerprinting risk"},
    512:  {"service": "rexec",      "risk": "critical", "notes": "Remote Exec — legacy; no encryption, no auth by default"},
    513:  {"service": "rlogin",     "risk": "critical", "notes": "Remote Login — trust-based auth; extremely dangerous"},
    514:  {"service": "Syslog/RSH", "risk": "critical", "notes": "Syslog or Remote Shell — unauthenticated command execution risk"},
    515:  {"service": "LPD",        "risk": "medium",   "notes": "Line Printer Daemon — information disclosure"},
    587:  {"service": "SMTP-Sub",   "risk": "low",      "notes": "SMTP Submission — requires authentication"},
    631:  {"service": "IPP",        "risk": "medium",   "notes": "Internet Printing Protocol — printer exposure"},
    636:  {"service": "LDAPS",      "risk": "low",      "notes": "LDAP over SSL"},
    993:  {"service": "IMAPS",      "risk": "low",      "notes": "IMAP over SSL"},
    995:  {"service": "POP3S",      "risk": "low",      "notes": "POP3 over SSL"},
    1080: {"service": "SOCKS",      "risk": "high",     "notes": "SOCKS Proxy — open proxy risk"},
    1194: {"service": "OpenVPN",    "risk": "medium",   "notes": "OpenVPN endpoint"},
    1433: {"service": "MSSQL",      "risk": "critical", "notes": "Microsoft SQL Server — direct database exposure"},
    1434: {"service": "MSSQL-M",    "risk": "critical", "notes": "MSSQL Monitor — Slammer worm target"},
    1521: {"service": "Oracle DB",  "risk": "critical", "notes": "Oracle Database — direct database exposure"},
    1723: {"service": "PPTP",       "risk": "high",     "notes": "PPTP VPN — weak encryption (MS-CHAPv2)"},
    2049: {"service": "NFS",        "risk": "high",     "notes": "Network File System — can expose filesystem if misconfigured"},
    2121: {"service": "FTP-alt",    "risk": "medium",   "notes": "Alternate FTP port"},
    2181: {"service": "Zookeeper",  "risk": "high",     "notes": "Apache Zookeeper — unauthenticated by default"},
    2375: {"service": "Docker",     "risk": "critical", "notes": "Docker API (no TLS) — full container escape to host"},
    2376: {"service": "Docker-TLS", "risk": "medium",   "notes": "Docker API over TLS — verify cert"},
    2379: {"service": "etcd",       "risk": "critical", "notes": "etcd — Kubernetes config store; unauthenticated exposes secrets"},
    3000: {"service": "Dev Server", "risk": "medium",   "notes": "Common dev server (Node/Grafana) — should not be public"},
    3306: {"service": "MySQL",      "risk": "critical", "notes": "MySQL Database — direct DB exposure"},
    3389: {"service": "RDP",        "risk": "critical", "notes": "Remote Desktop — BlueKeep target; brute-force risk"},
    3690: {"service": "SVN",        "risk": "medium",   "notes": "Subversion — may expose source code"},
    4000: {"service": "Dev/ICQ",    "risk": "low",      "notes": "Various dev servers"},
    4444: {"service": "Metasploit", "risk": "critical", "notes": "Metasploit default shell — active compromise indicator"},
    4848: {"service": "GlassFish",  "risk": "high",     "notes": "GlassFish Admin Console"},
    5000: {"service": "Dev/Flask",  "risk": "medium",   "notes": "Common Flask/Python dev server"},
    5432: {"service": "PostgreSQL", "risk": "critical", "notes": "PostgreSQL Database — direct DB exposure"},
    5900: {"service": "VNC",        "risk": "critical", "notes": "VNC — often weak/no auth; full desktop exposure"},
    5984: {"service": "CouchDB",    "risk": "high",     "notes": "CouchDB — admin party mode exposes all data"},
    6379: {"service": "Redis",      "risk": "critical", "notes": "Redis — no auth by default; RCE via config write"},
    6443: {"service": "K8s API",    "risk": "critical", "notes": "Kubernetes API Server — cluster takeover risk"},
    7001: {"service": "WebLogic",   "risk": "critical", "notes": "WebLogic — multiple critical deserialization CVEs"},
    7077: {"service": "Spark",      "risk": "high",     "notes": "Apache Spark Master — command execution risk"},
    8080: {"service": "HTTP-Alt",   "risk": "medium",   "notes": "Alternate HTTP — proxy, dev, or management interface"},
    8081: {"service": "HTTP-Alt",   "risk": "medium",   "notes": "Alternate HTTP port"},
    8443: {"service": "HTTPS-Alt",  "risk": "medium",   "notes": "Alternate HTTPS — management or dev"},
    8888: {"service": "Jupyter",    "risk": "critical", "notes": "Jupyter Notebook — code execution without auth by default"},
    9000: {"service": "Various",    "risk": "medium",   "notes": "PHP-FPM, SonarQube, Portainer"},
    9090: {"service": "Prometheus", "risk": "high",     "notes": "Prometheus metrics — exposes internal infrastructure data"},
    9092: {"service": "Kafka",      "risk": "high",     "notes": "Apache Kafka — no auth by default"},
    9200: {"service": "Elastic",    "risk": "critical", "notes": "Elasticsearch — unauthenticated data access"},
    9300: {"service": "Elastic-T",  "risk": "high",     "notes": "Elasticsearch transport"},
    10250: {"service": "kubelet",   "risk": "critical", "notes": "Kubernetes kubelet API — container exec risk"},
    11211: {"service": "Memcached", "risk": "high",     "notes": "Memcached — no auth, amplification DDoS vector"},
    27017: {"service": "MongoDB",   "risk": "critical", "notes": "MongoDB — no auth by default; massive data leaks"},
    50070: {"service": "Hadoop",    "risk": "critical", "notes": "Hadoop NameNode — cluster data exposure"},
}

CVE_HINTS = {
    "SMB":        ["CVE-2017-0143 (EternalBlue/WannaCry)", "CVE-2020-0796 (SMBGhost)", "CVE-2021-44142 (Samba)"],
    "RDP":        ["CVE-2019-0708 (BlueKeep)", "CVE-2019-1181 (DejaBlue)", "CVE-2022-21990"],
    "Redis":      ["CVE-2022-0543", "CVE-2021-32675", "Unauthenticated CONFIG SET RCE"],
    "MongoDB":    ["CVE-2019-2389", "Unauthenticated access (default config)"],
    "Elasticsearch": ["CVE-2021-22145", "CVE-2020-7009", "Unauthenticated data exposure"],
    "Docker":     ["CVE-2019-5736 (runc)", "CVE-2020-15257 (Containerd)", "Host takeover via API"],
    "WebLogic":   ["CVE-2021-2394", "CVE-2020-14882", "CVE-2020-14750 (RCE)"],
    "Telnet":     ["Cleartext credentials", "No encryption", "MITM trivial"],
    "FTP":        ["Anonymous login", "Cleartext credentials", "CVE-2010-4221 (ProFTPD)"],
    "LDAP":       ["CVE-2021-44228 (Log4Shell via LDAP)", "Anonymous bind information disclosure"],
    "MSSQL":      ["CVE-2020-0618", "CVE-2019-1068", "xp_cmdshell RCE"],
    "MySQL":      ["CVE-2016-6662", "CVE-2020-2574", "Default root no-password"],
    "Oracle DB":  ["CVE-2021-2351", "CVE-2020-14871", "TNS listener attack"],
    "VNC":        ["CVE-2019-15681", "CVE-2018-15120", "Bruteforce/no-auth default"],
    "NFS":        ["CVE-2017-12132", "World-readable exports"],
    "Memcached":  ["CVE-2018-1000115", "Amplification DDoS (51k x factor)"],
    "Hadoop":     ["CVE-2018-8029", "Unauthenticated resource manager access"],
    "etcd":       ["Unauthenticated key enumeration", "Kubernetes secret exposure"],
    "Jupyter":    ["Unauthenticated code execution", "Reverse shell via notebook"],
    "Zookeeper":  ["CVE-2019-0201", "Unauthenticated admin commands"],
    "Kafka":      ["CVE-2023-25194", "No auth by default"],
    "OpenVPN":    ["CVE-2017-7479", "CVE-2020-11810"],
    "SNMP":       ["Default community strings (public/private)", "CVE-2017-6736"],
    "DNS":        ["CVE-2020-1350 (SIGRed)", "Zone transfer (AXFR) information disclosure"],
}

QUICK_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]

COMMON_PORTS = list(range(1, 1025))

TOP_1000_PORTS = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43,
    49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111,
    113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255,
    256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443,
    444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545,
    548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683,
    687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808,
    843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995,
    999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026,
    1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040,
    1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054,
    1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068,
    1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082,
    1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096,
    1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113,
    1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141,
    1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175,
    1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234,
    1236, 1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310,
    1311, 1322, 1328, 1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501,
    1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688,
    1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812,
    1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984,
    1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013,
    2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046,
    2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121,
    2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260,
    2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522,
    2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718,
    2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998, 3000, 3001,
    3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168,
    3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325,
    3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527,
    3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814,
    3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945,
    3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125,
    4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567,
    4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050,
    5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221,
    5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510,
    5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801,
    5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903,
    5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962,
    5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009,
    6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543,
    6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779,
    6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025,
    7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676,
    7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007,
    8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084,
    8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194,
    8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600,
    8649, 8651, 8652, 8654, 8701, 8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003,
    9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102,
    9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535,
    9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943,
    9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012,
    10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628,
    10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782,
    13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000,
    16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101,
    18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221,
    20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352,
    27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769,
    32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781,
    32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193,
    40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154,
    49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176,
    49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800,
    51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600,
    56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623,
    64680, 65000, 65129, 65389,
]


def get_service_info(port: int) -> dict:
    info = PORT_SERVICE_MAP.get(port, {})
    if info:
        service = info["service"]
        return {
            "service": service,
            "risk": info["risk"],
            "notes": info["notes"],
            "cve_hints": CVE_HINTS.get(service, []),
        }
    return {
        "service": f"unknown ({port}/tcp)",
        "risk": "info",
        "notes": "Unknown service",
        "cve_hints": [],
    }


def get_ports_for_scan_type(scan_type: str, start: int = 1, end: int = 1024, custom: str = "") -> list:
    if scan_type == "quick":
        return sorted(QUICK_PORTS)
    elif scan_type == "common":
        return list(range(1, 1025))
    elif scan_type == "full":
        return list(range(1, 65536))
    elif scan_type == "vuln":
        return sorted(PORT_SERVICE_MAP.keys())
    elif scan_type == "stealth":
        return sorted(TOP_1000_PORTS)
    elif scan_type == "custom":
        ports = []
        for part in custom.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    a, b = part.split("-", 1)
                    ports.extend(range(int(a), int(b) + 1))
                except ValueError:
                    pass
            elif part.isdigit():
                ports.append(int(part))
        return sorted(set(p for p in ports if 1 <= p <= 65535))
    return list(range(start, end + 1))
