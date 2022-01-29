from scapy.all import *

FTPconns = {}
failedFTP = {}

def FTPAnalysis(p):
    vals = p[Raw].load.strip().split()
    src = p[IP].src
    dst = p[IP].dst
    port = p[TCP].sport
    if vals[0] == b"USER":
        key = '%s->%s' % (src, dst)
        if key not in FTPconns:
            FTPconns[key] = {}
        FTPconns[key][port] = [vals[1].decode('utf-8'), 'login']
    elif vals[0] == b"PASS":
        key = '%s->%s' % (src, dst)
        if key in FTPconns and port in FTPconns[key]:
            FTPconns[key][port][1] = 'pass'
        else:
            print("[!] FTP PASS (%s) %s:%s" % (vals[1], key, port))
    elif vals[0] == b"530":
        key = '%s->%s' % (src, dst)
        prot = p[TCP].dport
        if key in FTPconns and port in FTPconns[key]:
            v = FTPconns[key].pop(port)
            if v[0] in failedFTP:
                failedFTP[v[0]] += 1
            else:
                failedFTP[v[0]] = 1
            print("[!] FTP 530 (%s) %s:%s" % (v[0], key, port))

SSHconns = {}
failedSSH = {}

def SSHAnalysis(p):
    sIP = p[IP].src
    cIP = p[IP].dst
    key = '%s->%s' % (sIP, cIP)
    port = p[TCP].dport
    l = p[IP].len + 14
    if 'F' in p[TCP].flags:
        b = SSHconns[key].pop(port)
        b += 1
        if b < threshold:
            if key in failedSSH:
                failedSSH[key] += 1
            else:
                failedSSH[key] = 1
    else:
        if key not in SSHconns:
            SSHconns[key] = {}
        if port in SSHconns[key]:
            SSHconns[key][port] += 1
        else:
            if 'S' in p[TCP].flags:
                SSHconns[key][port] = 1


def analyzePacket(p):
    if p.haslayer(TCP):
        if (p[TCP].dport == 21) or (p[TCP].sport == 21) and p.haslayer(Raw):
            FTPAnalysis(p)
        elif p[TCP].sport == 22:
            SSHAnalysis(p)

def printResults(openConns, failed, protocol):
    print("[*] %s Connection Results:" % protocol)
    for conn in openConns:
        print("[+] %s: %s" % (conn, openConns[conn]))
    print("[*] %s Failed Connections:" % protocol)
    for conn in failed:
        print("[-] %s: %s" % (conn, failed[conn]))

sniff(offline="bruteforce.pcap", prn=analyzePacket)
sniff(offline="ssh.pcapng", prn=analyzePacket)
printResults(FTPconns, failedFTP, "FTP")
printResults(SSHconns, failedSSH, "SSH")