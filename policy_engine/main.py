import json
from datetime import datetime, timedelta

failed_login_history = {}
FAILURE_WINDOW_SECONDS = 60
FAILURE_THRESHOLD = 5

last_login_info = {}
IMPOSSIBLE_TRAVEL_SECONDS = 3600

known_user_ips = {}
UNUSUAL_HOUR_START = 0
UNUSUAL_HOUR_END = 5

known_user_programs = {}
PRIVILEGED_UIDS = [0]

user_activity_log = {}
ACTIVITY_WINDOW_SECONDS = 30
ACTIVITY_THRESHOLD = 10
PRIVIILEGED_UIDS = [0]

LARGE_TRANSFER_THRESHOLD = 50000000

recent_suspicious_spawns = {}

user_transfer_log = {}
CUMULATIVE_WINDOW_SECONDS = 120
CUMULATIVE_THRESHOLD = 100000000

def handle_event (raw_json) :

    event = json.loads (raw_json)

    event_type = event.get ("event_type", "unknow event type")

    print (f"Event type -> {event_type}")

    severity = "low"

    if event_type == "failed_login"  and event.get("user")== "root" :
        severity = "critical"
    elif event_type == "file_modification" :
        severity = "high"
    elif event_type == "logout" :
        severity = "info"

    print(f"Severity is {severity} ")

    if severity == "critical" :
        print("Severity is critical")
    else :
        print("Event processed")


# File Access

def file_access_check (event12) :
 watched_files = [
    "/etc/shadow",
    "/etc/passwd",
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
    "/etc/crontab",
    "/root/.ssh/authorized_keys",
    "/etc/hosts"
     ]
 expected_tools = {
     "/etc/shadow": [
         "/usr/bin/passwd",
         "/usr/sbin/usermod",
         "/usr/sbin/useradd",
         "/usr/sbin/chpasswd"
     ],
     "/etc/passwd": [
         "/usr/bin/passwd",
         "/usr/sbin/useradd",
         "/usr/sbin/userdel",
         "/usr/sbin/usermod"
     ],
     "/etc/ssh/sshd_config": [
         "/usr/bin/vim",
         "/usr/bin/nano",
         "/usr/sbin/sshd-config-tool"
     ],
     "/etc/sudoers": [
         "/usr/sbin/visudo"
     ],
     "/etc/crontab": [
         "/usr/bin/crontab"
     ],
     "/root/.ssh/authorized_keys": [
         "/usr/bin/ssh-copy-id",
         "/usr/bin/vim",
         "/usr/bin/nano"
     ],
     "/etc/hosts": [
         "/usr/bin/vim",
         "/usr/bin/nano"
     ]
 }

 event = json.loads (event12)
 event_type = event.get ("event_type", "unknow event type")
 if event_type == "file_modified" :
     path = event ["detail"]["path"]
     if path in watched_files :
       if path in expected_tools :
           exe_path = event["source"]["exe_path"]
           if exe_path in expected_tools[path] :
               return {"category": "File Access", "severity": "warning",
                       "reason": f"sensitive file modified by expected tool: {exe_path}", "event_id": event["event_id"]}
           else :
               return {"category": "File Access", "severity": "critical",
                       "reason": f"sensitive file modified by unexpected tool: {exe_path}",
                       "event_id": event["event_id"]}
       else :
           return {"category": "File Access", "severity": "critical",
                   "reason": f"sensitive file modified (no known baseline): {path}", "event_id": event["event_id"]}
     else :
         return {"category": "File Access", "severity": "info", "reason": "non-sensitive file modified", "event_id": event["event_id"]}
 else :
     return None

 #System Configuration


def check_sys_file_change (event12) :
    paths = [
        "/etc/",
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
        "/lib/",
        "/lib64/",
        "/boot/",
        "/usr/lib/",
        "/usr/local/bin/",
        "/var/spool/cron/",
    ]
    event = json.loads (event12)
    event_type = event.get ("event_type", "unknow event type")

    if event_type == "file_modified":
        path = event["detail"]["path"]
        for sys_path in paths:
            if path.startswith(sys_path):
                return {"category": "System Configuration", "severity": "warning",
                        "reason": f"system path modified: {path}", "event_id": event["event_id"]}

        return {"category": "System Configuration", "severity": "info",
                "reason": "non-system file modified", "event_id": event["event_id"]}
    else:
        return None

def check_sys_process (event12) :
    system_commands = [

        "apt", "apt-get", "yum", "dnf", "dpkg", "rpm", "snap",


        "systemctl", "service", "init",


        "useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod",
        "passwd", "chpasswd",


        "visudo", "chmod", "chown", "chgrp",


        "crontab", "at",


        "modprobe", "insmod", "rmmod", "sysctl",


        "iptables", "nft", "ufw", "firewall-cmd",


        "mount", "umount", "fdisk", "mkfs",
    ]
    event =json.loads (event12)
    event_type = event.get ("event_type", "unknow event type")
    if event_type == "process_spawn" :
        cmdline = event["source"]["cmdline"]
        for cmds in system_commands :
            if cmds in cmdline :
                return {"category": "System Configuration", "severity": "warning", "reason": f"system command executed: {cmdline}", "event_id": event["event_id"]}
        return {"category": "System Configuration", "severity": "info", "reason": "non-system process spawned", "event_id": event["event_id"]}
    else :
        return None

def check_network_behaviour (event12) :
    ports = [
        4444, 1337, 31337, 6666, 6667, 12345, 54321,
        1234, 4321, 9999, 8888, 27374, 20034,
        4443, 8080, 8443,
        31338, 12346, 65535,
        8081, 9001, 9050
        ]

    ips = [
        "192.168.",  # common private LAN range
        "10.",  # common private LAN range (larger networks)
        "172.16.",  # private LAN range (start of 172.16.0.0 - 172.31.255.255 block)
        "127.",  # localhost/loopback
    ]

    event = json.loads(event12)
    event_type = event.get("event_type", "unknow event type")
    if event_type == "net_connection":
        remote_port = event["detail"]["remote_port"]

        if remote_port in ports:
            ip = event["detail"]["remote_addr"]
            for target in ips:
                if ip.startswith(target):
                    return {"category": "Network Behaviour", "severity": "warning",
                            "reason": f"connection to suspicious port {remote_port} from trusted IP: {ip}",
                            "event_id": event["event_id"]}
            return {"category": "Network Behaviour", "severity": "critical",
                    "reason": f"connection to suspicious port {remote_port} from untrusted IP: {ip}",
                    "event_id": event["event_id"]}
        else:
            return {"category": "Network Behaviour", "severity": "info",
                    "reason": "normal network connection", "event_id": event["event_id"]}

    else :
          return None

def check_failed_login_history(event12):
    event = json.loads(event12)
    event_type = event.get("event_type", "unknown_event_type")

    if event_type != "login":
        return None

    status = event["detail"]["status"]
    if status != "failed":
        return None

    username = event["detail"]["username"]
    current_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))

    if username not in failed_login_history:
        failed_login_history[username] = []
    failed_login_history[username].append(current_time)

    cutoff = current_time - timedelta(seconds=FAILURE_WINDOW_SECONDS)
    failed_login_history[username] = [
        t for t in failed_login_history[username] if t >= cutoff
    ]

    recent_failures = len(failed_login_history[username])

    if recent_failures >= FAILURE_THRESHOLD:
        return {"category": "Normal Login", "severity": "critical",
                "reason": f"{recent_failures} failed logins for {username} in {FAILURE_WINDOW_SECONDS}s",
                "event_id": event["event_id"]}
    else:
        return {"category": "Normal Login", "severity": "info",
                "reason": f"failed login attempt for {username} ({recent_failures} recent)",
                "event_id": event["event_id"]}

def check_last_location (event13):
    event = json.loads(event13)
    event_type = event.get("event_type", "unknown_event_type")
    if event_type != "login":
        return None

    status = event["detail"]["status"]
    if status != "success":
        return None

    username = event["detail"]["username"]
    current_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    location = event["detail"]["location"]

    if username not in last_login_info :
       last_login_info[username] = {"location": location, "time": current_time}
       return {"category": "Normal Login", "severity": "info",
            "reason": f"first recorded login for {username}", "event_id": event["event_id"]}


    stored_location = last_login_info[username]["location"]
    stored_time = last_login_info[username]["time"]

    if location == stored_location:
        last_login_info[username] = {"location": location, "time": current_time}
        return {"category": "Normal Login", "severity": "info",
                "reason": f"login from same location as before: {location}",
                "event_id": event["event_id"]}
    time_gap = (current_time - stored_time).total_seconds()
    if time_gap < IMPOSSIBLE_TRAVEL_SECONDS:
        last_login_info[username] = {"location": location, "time": current_time}
        return {"category": "Normal Login", "severity": "critical",
                "reason": f"impossible travel: {username} went from {stored_location} to {location} in {int(time_gap)}s",
                "event_id": event["event_id"]}
    else:
        last_login_info[username] = {"location": location, "time": current_time}
        return {"category": "Normal Login", "severity": "warning",
                "reason": f"location changed: {username} went from {stored_location} to {location} after {int(time_gap)}s",
                "event_id": event["event_id"]}


def check_login_ceiling(event12):
    event = json.loads(event12)
    event_type = event.get("event_type", "unknown_event_type")
    if event_type != "login":
        return None

    status = event["detail"]["status"]
    if status != "success":
        return None

    username = event["detail"]["username"]
    source_ip = event["detail"]["source_ip"]
    current_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))

    is_unusual_hour = UNUSUAL_HOUR_START <= current_time.hour <= UNUSUAL_HOUR_END

    if username not in known_user_ips:
        known_user_ips[username] = set()

    is_new_ip = source_ip not in known_user_ips[username]

    known_user_ips[username].add(source_ip)

    if is_unusual_hour and is_new_ip:
        return {"category": "Normal Login", "severity": "critical",
                "reason": f"login at unusual hour ({current_time.hour}:00) from new IP: {source_ip}",
                "event_id": event["event_id"]}
    elif is_unusual_hour or is_new_ip:
        return {"category": "Normal Login", "severity": "warning",
                "reason": f"login flagged one signal (unusual_hour={is_unusual_hour}, new_ip={is_new_ip}) from {source_ip}",
                "event_id": event["event_id"]}
    else:
        return {"category": "Normal Login", "severity": "info",
                "reason": f"normal login from known IP: {source_ip}",
                "event_id": event["event_id"]}

def check_user (event46) :
    event = json.loads(event46)
    event_type = event.get("event_type", "unknown_event_type")
    if event_type != "process_spawn":
        return None

    uid = event["source"]["uid"]
    euid = event["source"]["euid"]
    exe_path = event["source"]["exe_path"]
    if uid not in known_user_programs:
        known_user_programs[uid] = set()
    if exe_path in  known_user_programs[uid]:
        known_user_programs[uid].add(exe_path)   # <-- ADDED (harmless here, already in set)
        return {"category": "User Behaviour", "severity": "info",
        "reason": f"known program executed by uid {uid}: {exe_path}",
        "event_id": event["event_id"]}
    else :
        known_user_programs[uid].add(exe_path)   # <-- ADDED (this is the important one - first time seeing it, now remember it)
        if euid in PRIVILEGED_UIDS :
            return {"category": "User Behaviour", "severity": "critical",   # <-- CHANGED from "warning"
                    "reason": f"new program for uid {uid}: {exe_path}",
                    "event_id": event["event_id"]}
        else :
            return {"category": "User Behaviour", "severity": "warning",   # <-- CHANGED from "critical"
                    "reason": f"privileged uid {uid} (euid {euid}) ran new program: {exe_path}",
                    "event_id": event["event_id"]}

def check_user_activity_burst(event78):
    event = json.loads(event78)
    uid = event["source"]["uid"]
    euid = event["source"]["euid"]
    current_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    if uid not in user_activity_log:
        user_activity_log[uid] = []
    user_activity_log[uid].append(current_time)

    cutoff = current_time - timedelta(seconds=ACTIVITY_WINDOW_SECONDS)
    user_activity_log[uid] = [t for t in user_activity_log[uid] if t >= cutoff]

    recent_count = len(user_activity_log[uid])

    if recent_count < ACTIVITY_THRESHOLD:
        return {"category": "User Behaviour", "severity": "info",
                "reason": f"normal activity pace for uid {uid} ({recent_count} actions in {ACTIVITY_WINDOW_SECONDS}s)",
                "event_id": event["event_id"]}
    elif euid in PRIVIILEGED_UIDS:
        return {"category": "User Behaviour", "severity": "critical",
                "reason": f"privileged uid {uid} activity burst: {recent_count} actions in {ACTIVITY_WINDOW_SECONDS}s",
                "event_id": event["event_id"]}
    else:
        return {"category": "User Behaviour", "severity": "warning",
                "reason": f"activity burst for uid {uid}: {recent_count} actions in {ACTIVITY_WINDOW_SECONDS}s",
                "event_id": event["event_id"]}

def check_privilege_escalation_chain(event):
    event_type = event["event_type"]
    uid = event["source"]["uid"]

    if event_type == "process_spawn":
        is_setuid = event["detail"].get("is_setuid", False)
        if is_setuid:
            recent_suspicious_spawns[uid] = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        return None

    if event_type == "privilege_change":
        current_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        if uid in recent_suspicious_spawns:
            gap = (current_time - recent_suspicious_spawns[uid]).total_seconds()
            if gap <= 30:
                return {"category": "User Behaviour", "severity": "critical",
                        "reason": f"privilege escalation chain: uid {uid} had suspicious spawn {int(gap)}s before privilege change",
                        "event_id": event["event_id"]}
        return {"category": "User Behaviour", "severity": "info",
                "reason": f"privilege change for uid {uid}, no recent suspicious spawn", "event_id": event["event_id"]}

    return None

def check_bytes_threshold (event12) :
    ipss = [
        "192.168.",
        "10.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "127.",
        "169.254.",
    ]
    event = json.loads(event12)
    event_type = event.get("event_type", "unknown_event_type")

    if event_type == "net_connection":
        bytes_sent = event["detail"].get("bytes_sent", 0)  # v2 field; defaults to 0 under v1 schema so this rule stays dormant instead of crashing
        if bytes_sent > LARGE_TRANSFER_THRESHOLD :
            remote_addr = event["detail"]["remote_addr"]
            for ip in ipss :
               if remote_addr.startswith(ip) :
                   return {"category": "Data Transfer", "severity": "warning",
                               "reason": f"large transfer to trusted destination: {bytes_sent} bytes to {remote_addr}",
                                 "event_id": event["event_id"]}
            return {"category": "Data Transfer", "severity": "critical",
                    "reason": f"large transfer to untrusted destination: {bytes_sent} bytes to {remote_addr}",
                    "event_id": event["event_id"]}
        else :
            return {"category": "Data Transfer", "severity": "info",
                    "reason": f"normal transfer volume: {bytes_sent} bytes",
                    "event_id": event["event_id"]}
    else :
        return None

def check_cumulative_transfer(event12):
    event = json.loads(event12)
    event_type = event.get("event_type", "unknown_event_type")
    if event_type != "net_connection":
        return None

    uid = event["source"]["uid"]
    bytes_sent = event["detail"].get("bytes_sent", 0)  # v2 field; defaults to 0 under v1 schema so this rule stays dormant instead of crashing
    current_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))

    if uid not in user_transfer_log:
        user_transfer_log[uid] = []
    user_transfer_log[uid].append((current_time, bytes_sent))

    cutoff = current_time - timedelta(seconds=CUMULATIVE_WINDOW_SECONDS)
    user_transfer_log[uid] = [pair for pair in user_transfer_log[uid] if pair[0] >= cutoff]

    total_bytes = sum(pair[1] for pair in user_transfer_log[uid])

    if total_bytes >= CUMULATIVE_THRESHOLD:
        return {"category": "Data Transfer", "severity": "critical",
                "reason": f"cumulative transfer for uid {uid}: {total_bytes} bytes in {CUMULATIVE_WINDOW_SECONDS}s",
                "event_id": event["event_id"]}
    else:
        return {"category": "Data Transfer", "severity": "info",
                "reason": f"cumulative transfer within normal range for uid {uid}: {total_bytes} bytes in {CUMULATIVE_WINDOW_SECONDS}s",
                "event_id": event["event_id"]}