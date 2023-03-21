# Brutreforce event detection
This code uses the win32evtlog module to query the Windows event log and detect brute-force attacks by parsing event logs with Event ID 4625, which corresponds to failed logon attempts.

Here is a brief explanation of the code:

The server variable is set to 'localhost', which specifies that the local machine's event log will be queried.

The logType variable is set to 'Security', which specifies that the Security event log will be queried.

The flags variable is set to a combination of EVENTLOG_FORWARD_READ and EVENTLOG_SEQUENTIAL_READ, which specifies that the event log will be read in a forward direction.

The QueryEventLog() function takes an EventID argument, which corresponds to the event ID of the Windows event log that will be queried. If a filename argument is provided, the function will query a backup event log file. The function iterates over the event log records and checks if the Event ID matches the provided EventID. If it does, the event record is appended to the logs list.

The DetectBruteForce() function calls QueryEventLog() with an EventID of 4625, which corresponds to failed logon attempts. It then iterates over the event log records and checks if the logon type (event.StringInsert[10]) matches any of the values [3, 8, 10]. These values correspond to network logon, remote interactive logon, and remote desktop logon. If the logon type matches, the function increments the failure count for the corresponding user account.

The filename variable is set to 'events.evtx', which specifies the name of the backup event log file that will be queried.

The DetectBruteForce() function is called with the filename argument, and the results are stored in the failures dictionary.

Finally, the failures dictionary is iterated over and the account name and corresponding failure count are printed to the console.

# Bruteforce network detection
This code performs network packet analysis on two different protocols, FTP and SSH, to detect brute force attacks. The code imports the scapy library for parsing and analyzing packets.

The FTPAnalysis() function processes the packet if it has the TCP port 21 (FTP data) and checks for USER, PASS, and 530 response codes. If it receives a USER command, it creates a dictionary of open connections and stores the username and login status. If it receives a PASS command, it updates the dictionary to indicate that the password has been entered. If it receives a 530 response code, it checks whether the previous login attempt was successful or not, and increments a counter for failed login attempts.

The SSHAnalysis() function processes the packet if it has the TCP port 22 (SSH data) and checks for failed login attempts. It creates a dictionary of open connections and stores the source and destination IP addresses, port number, and packet length. If the packet has the F flag (FIN flag) set, it increments a counter to track the number of failed login attempts. If the packet doesn't have the F flag, it checks whether the packet has the S flag (SYN flag) set, and updates the dictionary accordingly.

The analyzePacket() function is called by the sniff() function and determines whether the packet should be analyzed further by checking if it has the TCP protocol and whether it has the FTP or SSH ports.

The printResults() function is called at the end of the code and displays the results of the analysis. It takes two dictionaries as input, one for successful connections and another for failed connections, and prints the contents of these dictionaries to the console.

Finally, the code calls sniff() to capture packets from two different packet capture files, bruteforce.pcap and ssh.pcapng, and pass them to the analyzePacket() function. It then calls printResults() to print the results of the analysis to the console.
