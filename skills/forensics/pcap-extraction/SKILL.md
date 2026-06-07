---
name: pcap-extraction
description: >
  Use for packet captures where the answer needs tool-specific extraction
  recipes the model doesn't keep straight: USB HID keystroke decoding from
  `usb.capdata` (the keycode→character map is fiddly), TLS keylog
  reconstruction via SSLKEYLOGFILE, file carving from HTTP/SMB/FTP streams
  via Wireshark export-objects or tcpflow, credential extraction from
  unencrypted protocols, and non-obvious tshark display-filter / scapy
  reassembly work. Skip this skill when `strings cap.pcap | grep -aE
  'flag\{'` solves it (often does for small CTF pcaps), for fully-encrypted
  captures with no keys available, and for QUIC/WireGuard captures where
  the HTTP/TLS-flavoured recipes don't apply — try the cheap path first.
---

# PCAP Extraction Recipes

Tool-specific recipes for the cases where a generic `tshark -Y http` won't get you to the flag. **Always try `strings cap.pcap | grep -aE 'flag\{'` first** — it solves a large fraction of CTF pcaps in one second.

All artifacts go into `output/`.

## Triage (only run what informs the next step)

```bash
mkdir -p output
PCAP="<path-to-pcap>"
capinfos "$PCAP" 2>/dev/null | tee output/capture_info.txt
tshark -r "$PCAP" -q -z io,phs | tee output/protocol_hierarchy.txt
```

The protocol hierarchy tells you which recipe below applies. Skip to the matching section — don't enumerate every protocol.

## USB HID keystroke decoding

The trip-up: keystroke captures store HID reports in `usb.capdata` as 8-byte frames where byte 2 is the keycode and byte 0 bit 0x22 indicates shift. The HID keycode → character map is non-obvious.

```bash
tshark -r "$PCAP" -Y 'usb.capdata && usb.data_len == 8' \
  -T fields -e usb.capdata | tee output/usb_capdata.txt
```

Decode (covers letters, digits, common punctuation, shift handling):

```python
#!/usr/bin/env python3
KEYS = {
    0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x0b:'h',
    0x0c:'i',0x0d:'j',0x0e:'k',0x0f:'l',0x10:'m',0x11:'n',0x12:'o',0x13:'p',
    0x14:'q',0x15:'r',0x16:'s',0x17:'t',0x18:'u',0x19:'v',0x1a:'w',0x1b:'x',
    0x1c:'y',0x1d:'z',
    0x1e:'1',0x1f:'2',0x20:'3',0x21:'4',0x22:'5',0x23:'6',0x24:'7',0x25:'8',
    0x26:'9',0x27:'0',
    0x28:'\n',0x2a:'<BS>',0x2b:'\t',0x2c:' ',0x2d:'-',0x2e:'=',0x2f:'[',
    0x30:']',0x31:'\\',0x33:';',0x34:"'",0x35:'`',0x36:',',0x37:'.',0x38:'/',
}
SHIFT = {'1':'!','2':'@','3':'#','4':'$','5':'%','6':'^','7':'&','8':'*',
         '9':'(','0':')','-':'_','=':'+','[':'{',']':'}','\\':'|',';':':',
         "'":'"','`':'~',',':'<','.':'>','/':'?'}
out = ""
with open("output/usb_capdata.txt") as f:
    for line in f:
        b = bytes.fromhex(line.strip().replace(":",""))
        if len(b) != 8 or b[2] == 0:
            continue
        c = KEYS.get(b[2], "")
        if b[0] & 0x22:  # left or right shift
            c = SHIFT.get(c, c.upper())
        out += c
print(out)
```

For mouse/click captures use `usbhid.data` and decode bytes 1–2 as signed int8 dx,dy.

## TLS decryption

The trip-up: tshark needs the right key parameter and only RSA key exchange works with a private key — ECDHE requires a keylog file.

```bash
# With SSLKEYLOGFILE (works for ECDHE, modern TLS)
tshark -r "$PCAP" -o tls.keylog_file:<path-to-keylog> \
  -Y "http" -T fields \
  -e http.request.method -e http.host -e http.request.uri -e http.file_data \
  | tee output/tls_decrypted_http.txt

# Export decrypted objects after keylog is configured
tshark -r "$PCAP" -o tls.keylog_file:<path-to-keylog> \
  --export-objects http,output/decrypted_http_objects 2>/dev/null

# With RSA private key (ONLY works for RSA key exchange, not ECDHE)
tshark -r "$PCAP" \
  -o "tls.keys_list:0.0.0.0,443,http,<path-to-key.pem>" \
  -Y "http" | tee output/tls_decrypted.txt
```

Hunt for keylog files inside the pcap itself — sometimes embedded in HTTP responses, web page sources, or filesystem images:

```bash
strings "$PCAP" | grep -E 'CLIENT_RANDOM|RSA Session-ID|CLIENT_HANDSHAKE_TRAFFIC_SECRET'
```

## File carving from streams

```bash
# tshark export-objects — works for http, smb, dicom, tftp, imf, ftp-data
mkdir -p output/objects/{http,smb,tftp,imf}
for proto in http smb tftp imf; do
  tshark -r "$PCAP" --export-objects $proto,output/objects/$proto 2>/dev/null
done
find output/objects -type f -exec file {} \; | tee output/objects_types.txt

# When export-objects misses (custom/non-standard streams), reassemble with
# tcpflow then carve with foremost
mkdir -p output/tcpflow output/carved
tcpflow -r "$PCAP" -o output/tcpflow 2>/dev/null
foremost -i output/tcpflow/* -o output/carved 2>/dev/null
```

## NTLM / Kerberos hash extraction

The trip-up: the field names are non-obvious and the hashcat format is specific.

```bash
# NTLMv2 — capture the four fields needed for hashcat mode 5600
tshark -r "$PCAP" -Y "ntlmssp.messagetype == 0x00000003" -T fields \
  -e ntlmssp.auth.username -e ntlmssp.auth.domain \
  -e ntlmssp.ntlmv2_response.ntproofstr \
  -e ntlmssp.ntlmv2_response \
  | tee output/ntlmv2_components.txt

# Kerberos AS-REQ → roasting candidates (hashcat mode 18200)
tshark -r "$PCAP" -Y "kerberos.msg_type == 10" -T fields \
  -e kerberos.CNameString -e kerberos.realm -e kerberos.cipher \
  | tee output/kerberos_asreq.txt
```

Reassemble into hashcat format manually — the fields above are the inputs.

## Plaintext credentials (HTTP Basic, FTP, IMAP/POP3, Telnet)

```bash
# HTTP Basic Auth — base64 in the header
tshark -r "$PCAP" -Y "http.authorization" -T fields -e http.authorization \
  | grep -oP 'Basic \K[A-Za-z0-9+/=]+' \
  | while read b64; do echo "$b64 -> $(echo "$b64" | base64 -d)"; done

# FTP / IMAP / POP3 / Telnet — credentials are visible in command/data fields
tshark -r "$PCAP" \
  -Y "ftp.request.command in {USER PASS} || imap.request || pop.request || telnet.data" \
  | tee output/plaintext_creds.txt
```

## Beaconing detection (timing analysis)

C2 callbacks produce regular intervals. Extract timestamps per destination, then look for low coefficient-of-variation:

```bash
tshark -r "$PCAP" -T fields -e ip.dst -e frame.time_epoch | sort > output/dst_times.txt
```

```python
#!/usr/bin/env python3
from collections import defaultdict
conns = defaultdict(list)
for line in open("output/dst_times.txt"):
    parts = line.strip().split('\t')
    if len(parts) == 2:
        conns[parts[0]].append(float(parts[1]))
for ip, ts in conns.items():
    if len(ts) < 5: continue
    iv = [ts[i+1]-ts[i] for i in range(len(ts)-1)]
    avg = sum(iv)/len(iv)
    sd = (sum((x-avg)**2 for x in iv)/len(iv))**0.5
    if sd < avg*0.15 and avg > 1:
        print(f"BEACON {ip} count={len(ts)} avg={avg:.1f}s sd={sd:.1f}s")
```

## Wireless (802.11) extraction

Only relevant if `protocol_hierarchy.txt` shows `wlan`. WPA handshakes for cracking:

```bash
# EAPOL frames (4-way handshake → hashcat mode 22000)
tshark -r "$PCAP" -Y "eapol" -w output/eapol.pcap
hcxpcapngtool -o output/wpa.hc22000 output/eapol.pcap 2>&1

# Probe requests reveal device-history SSIDs
tshark -r "$PCAP" -Y "wlan.fc.type_subtype == 0x04" -T fields \
  -e wlan.sa -e wlan.ssid | sort -u
```

## Custom dissection with scapy

When tshark's filters can't express what you need (custom protocols, fragmented payloads, stateful reassembly), use scapy for full programmatic access:

```python
from scapy.all import rdpcap, TCP, Raw
packets = rdpcap("<path-to-pcap>")
# Reassemble TCP stream by (src,dst,sport,dport) and concatenate Raw payloads in seq order.
# Filter, decode, extract — full Python control over every byte.
```

## After extraction

Every carved file may itself contain steg/embedded payloads. Run a quick check inline before continuing:

```bash
F="<extracted-file>"
file "$F"; exiftool "$F"; strings "$F" | grep -iE 'flag\{|ctf\{'
binwalk "$F"
# If clearly a stego candidate (PNG/BMP/JPEG/WAV), apply file-repair-and-stego skill.
```

If multiple files need deeper analysis (LSB sweeps, stegseek bruteforce, OLE macro extraction), **stop and return the list** so the caller can spawn parallel `file-repair-and-stego` subagents.
