---
name: network-forensics
description: >
  Analyze network packet captures (pcap/pcapng) using tshark, tcpdump, scapy,
  and related tools. Use this skill whenever the user has a pcap or pcapng file
  and wants to analyze network traffic — extract conversations, reconstruct
  streams, carve transferred files, find credentials, inspect DNS queries,
  analyze TLS certificates, detect anomalies, or investigate network-based
  attacks. Also trigger when the user mentions network forensics, packet
  analysis, pcap analysis, tshark, wireshark, tcpdump, scapy, "analyze this
  capture", "what traffic is in this pcap", "extract files from pcap",
  "find credentials in traffic", "reconstruct sessions", protocol analysis,
  traffic analysis, or any task involving network capture investigation.
  Trigger on any mention of tshark filters, wireshark display filters,
  BPF filters, or network forensics techniques.
---

# Network Forensics Skill

Analyze packet captures (pcap/pcapng) to extract conversations, reconstruct
sessions, carve files, find credentials, and identify suspicious activity.

Primary tools: **tshark**, **tcpdump**, **scapy**, **pyshark**, **dpkt**.
Supporting tools: **tcpflow**, **chaosreader**, **ngrep**, **ssldump**,
**foremost**, **dsniff** utilities.

All analysis artifacts go into `output/` relative to the working directory.

## Step 1: Initial Triage

Always start here. Understand the capture before diving into specifics.

```bash
mkdir -p output
PCAP="<path-to-pcap>"
```

### 1a. File Identification

```bash
file "$PCAP" | tee output/file_type.txt
capinfos "$PCAP" 2>/dev/null | tee output/capture_info.txt
```

`capinfos` gives: file format, encapsulation, packet count, capture duration,
data rate, start/end timestamps, and file size. This sets the scope for the
entire analysis.

### 1b. Protocol Hierarchy

```bash
tshark -r "$PCAP" -q -z io,phs | tee output/protocol_hierarchy.txt
```

This reveals which protocols are present and their relative volume. Use it
to decide which analysis steps to prioritize — skip HTTP analysis if there
is no HTTP traffic.

### 1c. Quick Packet Sample

Preview the first 50 packets to get a feel for the traffic:

```bash
tshark -r "$PCAP" -c 50 | tee output/first_50_packets.txt
```

For a more detailed view with full dissection:

```bash
tshark -r "$PCAP" -c 20 -V > output/first_20_verbose.txt
```

### 1d. Endpoint and Conversation Summary

```bash
# Top talkers by IP
tshark -r "$PCAP" -q -z endpoints,ip | tee output/endpoints_ip.txt

# Top conversations
tshark -r "$PCAP" -q -z conv,tcp | tee output/conversations_tcp.txt
tshark -r "$PCAP" -q -z conv,udp | tee output/conversations_udp.txt
```

Identify the key IP addresses and which pairs exchanged the most data.
This focuses the investigation.

## Step 2: Protocol-Specific Analysis

Run only the sections relevant to protocols found in Step 1b.

### 2a. DNS Analysis

```bash
# All DNS queries and responses
tshark -r "$PCAP" -Y "dns" -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e dns.qry.name -e dns.qry.type \
  -e dns.a -e dns.aaaa -e dns.cname -e dns.txt \
  -E header=y -E separator=, \
  | tee output/dns_queries.csv

# Unique queried domains
tshark -r "$PCAP" -Y "dns.qry.name" -T fields -e dns.qry.name \
  | sort -u | tee output/dns_unique_domains.txt

# TXT records (often used for data exfil or C2)
tshark -r "$PCAP" -Y "dns.txt" -T fields \
  -e dns.qry.name -e dns.txt \
  | tee output/dns_txt_records.txt
```

**DNS tunneling detection** — look for unusually long subdomain labels,
high query volume to a single domain, or TXT record abuse:

```bash
# Domains with long labels (potential tunneling)
tshark -r "$PCAP" -Y "dns.qry.name" -T fields -e dns.qry.name \
  | awk -F. '{for(i=1;i<=NF;i++) if(length($i)>30) print}' \
  | sort -u | tee output/dns_long_labels.txt

# Query frequency per domain (top 20)
tshark -r "$PCAP" -Y "dns.flags.response == 0" -T fields -e dns.qry.name \
  | sort | uniq -c | sort -rn | head -20 \
  | tee output/dns_query_frequency.txt
```

### 2b. HTTP Analysis

```bash
# HTTP requests summary
tshark -r "$PCAP" -Y "http.request" -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e http.request.method -e http.host \
  -e http.request.uri -e http.user_agent \
  -E header=y -E separator='|' \
  | tee output/http_requests.csv

# HTTP responses with status codes
tshark -r "$PCAP" -Y "http.response" -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e http.response.code -e http.content_type \
  -e http.content_length \
  -E header=y -E separator='|' \
  | tee output/http_responses.csv

# Unique URIs
tshark -r "$PCAP" -Y "http.request.uri" -T fields \
  -e http.host -e http.request.uri \
  | sort -u | tee output/http_unique_uris.txt

# Unique User-Agents
tshark -r "$PCAP" -Y "http.user_agent" -T fields -e http.user_agent \
  | sort -u | tee output/http_user_agents.txt
```

**Extract HTTP objects** (transferred files, pages, images):

```bash
mkdir -p output/http_objects
tshark -r "$PCAP" --export-objects http,output/http_objects 2>/dev/null
ls -la output/http_objects/ | tee output/http_objects_list.txt
```

After extraction, run `file` on each object to identify types, then
inspect interesting ones.

### 2c. HTTPS / TLS Analysis

```bash
# TLS Client Hello — SNI (Server Name Indication)
tshark -r "$PCAP" -Y "tls.handshake.type == 1" -T fields \
  -e ip.src -e ip.dst -e tcp.dstport \
  -e tls.handshake.extensions_server_name \
  -E header=y -E separator='|' \
  | tee output/tls_client_hello.csv

# Unique SNI values (domains contacted over TLS)
tshark -r "$PCAP" -Y "tls.handshake.extensions_server_name" \
  -T fields -e tls.handshake.extensions_server_name \
  | sort -u | tee output/tls_sni_domains.txt

# TLS certificates
tshark -r "$PCAP" -Y "tls.handshake.type == 11" -T fields \
  -e ip.src -e ip.dst \
  -e x509sat.utf8String \
  -e x509sat.printableString \
  -e x509ce.dNSName \
  | tee output/tls_certificates.txt

# TLS versions in use
tshark -r "$PCAP" -Y "tls.handshake.type == 1" -T fields \
  -e tls.handshake.version -e tls.handshake.extensions_server_name \
  | sort | uniq -c | sort -rn | tee output/tls_versions.txt
```

**JA3 fingerprinting** (identify client applications by TLS fingerprint):

```bash
tshark -r "$PCAP" -Y "tls.handshake.type == 1" -T fields \
  -e ip.src -e tls.handshake.ja3 \
  -e tls.handshake.extensions_server_name \
  | sort -u | tee output/ja3_fingerprints.txt
```

**Decrypt TLS** if a key log file (SSLKEYLOGFILE) or private key is available:

```bash
# With SSLKEYLOGFILE
tshark -r "$PCAP" -o tls.keylog_file:<path-to-keylog> \
  -Y "http" -T fields \
  -e http.request.method -e http.host -e http.request.uri \
  | tee output/tls_decrypted_http.txt

# With RSA private key (only works for RSA key exchange, not ECDHE)
tshark -r "$PCAP" \
  -o "tls.keys_list:0.0.0.0,443,http,<path-to-key.pem>" \
  -Y "http" | tee output/tls_decrypted.txt
```

### 2d. SMTP / Email Analysis

```bash
# SMTP commands and responses
tshark -r "$PCAP" -Y "smtp" -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e smtp.req.command -e smtp.req.parameter \
  -e smtp.rsp.code -e smtp.rsp.parameter \
  | tee output/smtp_traffic.txt

# Email addresses (MAIL FROM / RCPT TO)
tshark -r "$PCAP" -Y "smtp.req.command == MAIL || smtp.req.command == RCPT" \
  -T fields -e smtp.req.parameter \
  | tee output/smtp_addresses.txt

# Extract email data from SMTP streams
tshark -r "$PCAP" -Y "smtp.data.fragment" -T fields -e smtp.data.fragment \
  > output/smtp_data_fragments.txt

# IMF (Internet Message Format) — parsed email headers
tshark -r "$PCAP" -Y "imf" -T fields \
  -e imf.from -e imf.to -e imf.subject -e imf.date \
  | tee output/email_headers.txt
```

### 2e. FTP Analysis

```bash
# FTP commands and responses
tshark -r "$PCAP" -Y "ftp" -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e ftp.request.command -e ftp.request.arg \
  -e ftp.response.code -e ftp.response.arg \
  | tee output/ftp_commands.txt

# FTP credentials
tshark -r "$PCAP" -Y "ftp.request.command == USER || ftp.request.command == PASS" \
  -T fields -e ip.src -e ftp.request.command -e ftp.request.arg \
  | tee output/ftp_credentials.txt

# FTP data transfers — extract via tcpflow
mkdir -p output/ftp_data
tcpflow -r "$PCAP" -o output/ftp_data "port 20 or port 21" 2>/dev/null
```

### 2f. SMB Analysis

```bash
# SMB file operations
tshark -r "$PCAP" -Y "smb2" -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e smb2.cmd -e smb2.filename \
  | tee output/smb_operations.txt

# SMB files accessed
tshark -r "$PCAP" -Y "smb2.filename" -T fields -e smb2.filename \
  | sort -u | tee output/smb_files.txt

# Extract SMB objects
mkdir -p output/smb_objects
tshark -r "$PCAP" --export-objects smb,output/smb_objects 2>/dev/null
ls -la output/smb_objects/ | tee output/smb_objects_list.txt
```

### 2g. SSH Analysis

SSH traffic is encrypted, but metadata is still valuable:

```bash
# SSH sessions
tshark -r "$PCAP" -Y "ssh" -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e tcp.srcport -e tcp.dstport \
  -e ssh.protocol \
  | tee output/ssh_sessions.txt

# SSH banners (version strings)
tshark -r "$PCAP" -Y "ssh.protocol" -T fields \
  -e ip.src -e ssh.protocol \
  | sort -u | tee output/ssh_banners.txt
```

### 2h. ICMP Analysis

```bash
tshark -r "$PCAP" -Y "icmp" -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e icmp.type -e icmp.code -e data.data \
  | tee output/icmp_traffic.txt
```

ICMP can be used for data exfiltration (ping tunneling). Check for
unusually large ICMP packets or data in the payload field.

### 2i. Telnet / Plaintext Protocol Analysis

```bash
# Telnet data (credentials often visible)
tshark -r "$PCAP" -Y "telnet" -T fields \
  -e frame.time -e ip.src -e ip.dst -e telnet.data \
  | tee output/telnet_traffic.txt
```

## Step 3: Stream Reconstruction

Reassemble full TCP/UDP sessions to see complete exchanges.

### 3a. TCP Stream Extraction with tshark

```bash
mkdir -p output/streams

# Count total TCP streams
STREAM_COUNT=$(tshark -r "$PCAP" -T fields -e tcp.stream \
  | sort -un | tail -1)
echo "Total TCP streams: $STREAM_COUNT" | tee output/stream_count.txt

# Follow a specific TCP stream (ASCII)
tshark -r "$PCAP" -q -z "follow,tcp,ascii,<stream_index>" \
  > output/streams/tcp_stream_<stream_index>.txt

# Follow a specific UDP stream
tshark -r "$PCAP" -q -z "follow,udp,ascii,<stream_index>" \
  > output/streams/udp_stream_<stream_index>.txt
```

When there are many streams, iterate over them programmatically and inspect
each for interesting content. Focus on streams involving suspicious IPs or
unusual ports identified in Step 1d.

### 3b. Bulk Stream Extraction with tcpflow

```bash
mkdir -p output/tcpflow
tcpflow -r "$PCAP" -o output/tcpflow 2>/dev/null
ls -lhS output/tcpflow/ | head -30 | tee output/tcpflow_files.txt
```

tcpflow creates one file per direction per stream. Largest files often
contain transferred data worth inspecting.

### 3c. Session Reconstruction with chaosreader

```bash
mkdir -p output/chaosreader
cd output/chaosreader && chaosreader "../../$PCAP" 2>/dev/null; cd -
```

chaosreader generates an HTML index with reconstructed sessions. It
automatically extracts HTTP content, email messages, telnet sessions,
and FTP transfers.

## Step 4: Credential Extraction

### 4a. Cleartext Credentials

```bash
# HTTP Basic Auth (Base64-encoded)
tshark -r "$PCAP" -Y "http.authorization" -T fields \
  -e ip.src -e http.host -e http.authorization \
  | tee output/http_auth.txt

# Decode Basic Auth headers
grep -oP 'Basic \K[A-Za-z0-9+/=]+' output/http_auth.txt \
  | while read -r b64; do echo "$b64 -> $(echo "$b64" | base64 -d 2>/dev/null)"; done \
  | tee output/http_auth_decoded.txt

# HTTP form POST data (login forms)
tshark -r "$PCAP" -Y "http.request.method == POST" -T fields \
  -e ip.src -e http.host -e http.request.uri \
  -e http.file_data \
  | tee output/http_post_data.txt

# FTP credentials (already in 2e, repeated for convenience)
tshark -r "$PCAP" \
  -Y "ftp.request.command == USER || ftp.request.command == PASS" \
  -T fields -e ip.src -e ftp.request.command -e ftp.request.arg \
  | tee output/ftp_creds.txt

# IMAP/POP3 logins
tshark -r "$PCAP" -Y "imap.request || pop.request" -T fields \
  -e ip.src -e ip.dst -e imap.request -e pop.request \
  | tee output/mail_creds.txt
```

### 4b. NTLM / Kerberos Hashes

```bash
# NTLMSSP authentication
tshark -r "$PCAP" -Y "ntlmssp" -T fields \
  -e ip.src -e ip.dst \
  -e ntlmssp.auth.username -e ntlmssp.auth.domain \
  -e ntlmssp.ntlmv2_response.ntproofstr \
  | tee output/ntlm_auth.txt

# Kerberos tickets
tshark -r "$PCAP" -Y "kerberos" -T fields \
  -e ip.src -e ip.dst \
  -e kerberos.CNameString -e kerberos.realm \
  -e kerberos.msg_type \
  | tee output/kerberos_traffic.txt
```

### 4c. Pattern-Based Credential Search

```bash
# Search raw packet payloads for credential keywords
ngrep -I "$PCAP" -q -W byline \
  'password|passwd|login|user|auth|token|secret|key' \
  2>/dev/null | tee output/ngrep_creds.txt
```

## Step 5: File Carving and Data Extraction

### 5a. Export Objects (tshark)

tshark can export objects from several protocols:

```bash
mkdir -p output/exported_objects/{http,smb,dicom,tftp,imf}

tshark -r "$PCAP" --export-objects http,output/exported_objects/http 2>/dev/null
tshark -r "$PCAP" --export-objects smb,output/exported_objects/smb 2>/dev/null
tshark -r "$PCAP" --export-objects dicom,output/exported_objects/dicom 2>/dev/null
tshark -r "$PCAP" --export-objects tftp,output/exported_objects/tftp 2>/dev/null
tshark -r "$PCAP" --export-objects imf,output/exported_objects/imf 2>/dev/null

# List everything extracted
find output/exported_objects -type f -exec file {} \; \
  | tee output/exported_objects_types.txt
```

### 5b. File Carving from Streams

When tshark's export doesn't catch everything, carve files from
reassembled streams:

```bash
mkdir -p output/carved_files

# Carve from tcpflow output
foremost -i output/tcpflow/* -o output/carved_files 2>/dev/null

# Or carve directly from the pcap (less precise)
foremost -i "$PCAP" -o output/carved_foremost 2>/dev/null

cat output/carved_files/audit.txt 2>/dev/null | tee output/carved_audit.txt
cat output/carved_foremost/audit.txt 2>/dev/null | tee -a output/carved_audit.txt
```

### 5c. Analyze Extracted Files in Parallel

**Every file extracted above (images, documents, archives, binaries) may
contain steganographic payloads, embedded data, or hidden flags that pcap
analysis alone will never find.**

Run these **quick file-forensics checks inline** on every extracted file
before continuing pcap analysis. These take seconds and catch the most
common CTF techniques:

```bash
FILE="<path-to-extracted-file>"
exiftool "$FILE" 2>&1
strings "$FILE" | grep -iE "flag\{|ctf\{|key\{|password|secret"
binwalk "$FILE" 2>&1
# JPEG/BMP/WAV → steghide (NEVER use 2>/dev/null — success msg is on stderr)
steghide extract -sf "$FILE" -p "" -xf output/steghide_extracted.bin 2>&1
cat output/steghide_extracted.bin 2>&1
# PNG/BMP → zsteg
zsteg "$FILE" 2>&1
```

If these quick checks find the flag, you're done. If not and the files
need deeper analysis (LSB bit-plane sweeps, stegseek bruteforce, PDF
parsing, OLE macro extraction, etc.), **STOP and return your findings**
so the caller can spawn dedicated file-forensics subagents in parallel
with continued pcap analysis. List the files and what deeper analysis
each needs.

Do NOT skip the quick checks. Do NOT defer them to the end. Steghide
with an empty password on a JPEG is one of the most common CTF
techniques and can only be found through file-level analysis.

### 5d. Extract Specific Data with Scapy

For custom extraction that tshark filters can't handle, use scapy:

```python
#!/usr/bin/env python3
"""Extract raw payloads from packets matching a filter."""
from scapy.all import rdpcap, TCP, UDP, Raw

packets = rdpcap("<path-to-pcap>")
for i, pkt in enumerate(packets):
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load
        # Process payload as needed
        with open(f"output/payload_{i}.bin", "wb") as f:
            f.write(payload)
```

For reassembling fragmented data across packets, extracting custom
protocol fields, or decoding non-standard encodings, write a targeted
scapy script. Scapy gives full programmatic access to every layer and
field.

## Step 6: Anomaly Detection

### 6a. Beaconing Detection

Regular-interval callbacks to a C2 server produce a distinctive timing
pattern:

```bash
# Extract timestamps per destination IP
tshark -r "$PCAP" -T fields -e ip.dst -e frame.time_epoch \
  | sort | tee output/dst_timestamps.txt
```

Then analyze timing intervals with a script — look for connections to the
same IP at consistent intervals (e.g., every 60s, every 300s).

```python
#!/usr/bin/env python3
"""Detect beaconing by analyzing connection intervals."""
import sys
from collections import defaultdict

connections = defaultdict(list)
with open("output/dst_timestamps.txt") as f:
    for line in f:
        parts = line.strip().split('\t')
        if len(parts) == 2:
            ip, ts = parts
            connections[ip].append(float(ts))

for ip, timestamps in sorted(connections.items()):
    if len(timestamps) < 5:
        continue
    intervals = [
        timestamps[i+1] - timestamps[i]
        for i in range(len(timestamps)-1)
    ]
    avg = sum(intervals) / len(intervals)
    stddev = (
        sum((x - avg) ** 2 for x in intervals) / len(intervals)
    ) ** 0.5
    if stddev < avg * 0.15 and avg > 1:
        print(
            f"BEACON: {ip} | count={len(timestamps)} "
            f"| avg_interval={avg:.1f}s | stddev={stddev:.1f}s"
        )
```

### 6b. Port and Protocol Anomalies

```bash
# Non-standard ports for known protocols (e.g., HTTP on port 8443)
tshark -r "$PCAP" -Y "tcp.port > 1024" -T fields \
  -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e frame.protocols \
  | sort | uniq -c | sort -rn | head -30 \
  | tee output/unusual_ports.txt

# Large DNS responses (possible exfiltration)
tshark -r "$PCAP" -Y "dns && udp.length > 512" -T fields \
  -e ip.src -e ip.dst -e dns.qry.name -e udp.length \
  | tee output/large_dns.txt
```

### 6c. Data Exfiltration Indicators

```bash
# Top data senders (potential exfil sources)
tshark -r "$PCAP" -q -z endpoints,ip \
  | sort -t'|' -k4 -rn | head -20 \
  | tee output/top_senders.txt

# Large outbound transfers
tshark -r "$PCAP" -Y "tcp.len > 1000" -T fields \
  -e ip.src -e ip.dst -e tcp.len \
  | awk '{sums[$1" -> "$2]+=$3} END {for(k in sums) print sums[k], k}' \
  | sort -rn | head -20 \
  | tee output/large_transfers.txt
```

## Step 7: Wireless-Specific Analysis

Only relevant for 802.11 (WiFi) captures.

```bash
# Check if capture contains wireless frames
tshark -r "$PCAP" -c 1 -T fields -e frame.protocols \
  | grep -q "wlan" && echo "Wireless capture detected"

# Wireless access points (beacons)
tshark -r "$PCAP" -Y "wlan.fc.type_subtype == 0x08" -T fields \
  -e wlan.ssid -e wlan.bssid -e wlan_radio.channel \
  | sort -u | tee output/wireless_aps.txt

# Probe requests (device enumeration)
tshark -r "$PCAP" -Y "wlan.fc.type_subtype == 0x04" -T fields \
  -e wlan.sa -e wlan.ssid \
  | sort -u | tee output/wireless_probes.txt

# Deauth frames (potential attack indicator)
tshark -r "$PCAP" -Y "wlan.fc.type_subtype == 0x0c" -T fields \
  -e wlan.sa -e wlan.da -e wlan.bssid \
  | tee output/wireless_deauths.txt
```

## Step 8: IoC Extraction

Consolidate indicators of compromise from all previous analysis.

```bash
# Extract all IPs from the capture
tshark -r "$PCAP" -T fields -e ip.src -e ip.dst \
  | tr '\t' '\n' | sort -u | grep -v '^$' \
  | tee output/all_ips.txt

# Filter to external IPs (exclude RFC1918 and link-local)
grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.)' \
  output/all_ips.txt | sort -u \
  | tee output/external_ips.txt

# All domains (from DNS + TLS SNI + HTTP Host)
cat output/dns_unique_domains.txt output/tls_sni_domains.txt 2>/dev/null \
  | sort -u | tee output/all_domains.txt
tshark -r "$PCAP" -Y "http.host" -T fields -e http.host \
  | sort -u >> output/all_domains.txt
sort -u -o output/all_domains.txt output/all_domains.txt

# All URLs
tshark -r "$PCAP" -Y "http.request.full_uri" -T fields \
  -e http.request.full_uri \
  | sort -u | tee output/all_urls.txt

# File hashes of extracted objects
find output/exported_objects -type f -exec sha256sum {} \; \
  | tee output/file_hashes.txt
```

## Step 9: Targeted Investigation

After initial analysis, drill into specific findings. Common scenarios:

### Suspicious IP or Domain

```bash
# All traffic to/from a specific IP
tshark -r "$PCAP" -Y "ip.addr == <IP>" | tee output/ip_<IP>_traffic.txt

# All traffic involving a specific domain
tshark -r "$PCAP" -Y "dns.qry.name contains \"<domain>\" || \
  http.host contains \"<domain>\" || \
  tls.handshake.extensions_server_name contains \"<domain>\"" \
  | tee output/domain_<domain>_traffic.txt
```

### Specific Stream Deep-Dive

```bash
# Follow and save a specific TCP stream as raw bytes
tshark -r "$PCAP" -q -z "follow,tcp,raw,<stream_index>" \
  > output/streams/tcp_stream_<stream_index>_raw.txt

# Extract just one side of a TCP stream
tshark -r "$PCAP" -Y "tcp.stream == <stream_index> && ip.src == <IP>" \
  -T fields -e tcp.payload \
  | tr -d ':' | xxd -r -p > output/stream_<stream_index>_payload.bin
```

### Encoded or Obfuscated Data

```bash
# Search all payloads for base64
ngrep -I "$PCAP" -q -W byline '[A-Za-z0-9+/]{20,}={0,2}' \
  2>/dev/null | tee output/base64_in_traffic.txt

# Search for hex-encoded data
ngrep -I "$PCAP" -q -W byline '[0-9a-fA-F]{40,}' \
  2>/dev/null | tee output/hex_in_traffic.txt
```

## Step 10: Synthesis and Reporting

After running relevant analysis steps, synthesize findings:

1. **Capture overview** — duration, packet count, protocols, key endpoints
2. **Communication map** — who talked to whom, on which ports/protocols
3. **Extracted artifacts** — files, credentials, certificates, emails
4. **Suspicious activity** — beaconing, exfiltration, tunneling, anomalies
5. **IoCs** — external IPs, domains, URLs, file hashes, user agents
6. **Timeline** — sequence of events reconstructed from packet timestamps
7. **Recommend next steps** — deeper analysis of extracted files (apply
   file-forensics skill), threat intel lookups for IoCs, decryption if
   keys become available

If extracted files need further analysis (malware, documents, images),
apply the **file-forensics** skill to each.
