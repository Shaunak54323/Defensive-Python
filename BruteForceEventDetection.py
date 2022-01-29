import win32evtlog

server = 'localhost'
logType = 'Security'
flags = win32evtlog.EVENTLOG_FORWARD_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

def QueryEventLog(EventID, filename = None):
    logs = []
    if not filename:
        h = win32evtlog.OpenEventLog(server, logType)
    else:
        h = win32evtlog.OpenBackupEventLog(server, filename)
    while True:
        events = win32evtlog.ReadEventLog(h, flags, 0)
        if events:
            for event in events:
                if event.EventID == EventID:
                    logs.append(event)
        else:
            break
    return logs


def DetectBruteForce(filename = None):
    failures = {}
    events = QueryEventLog(4625, filename)
    for event in events:
        if int(event.StringInsert[10]) in [3, 8, 10]:
            account = event.StringInsert[5]
            if account in failures:
                failures[account] += 1
            else:
                failures[account] = 1
    return failures

filename = 'events.evtx'
failures = DetectBruteForce(filename)
for account, count in failures.items():
    print(account, count)
