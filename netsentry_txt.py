#!/usr/bin/env python3
"""
NetSentry - Fast Network Packet Analysis Toolkit
Unified CLI tool for packet capture, analysis, and sensitive data detection
UPDATED: Added deduplication and filtering
"""

import subprocess
import signal
import shutil
import os
import datetime
import argparse
import sys
import json
import re
import base64
import hashlib
from scapy.all import sniff, Raw, TCP, IP, UDP
from typing import List, Dict, Any, Optional
from threading import Thread, Event
import time

# ==================== CONFIGURATION ====================
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), 'samples')
ALERT_FILE = "alerts.txt"
DEFAULT_INTERFACE = "eth0"

# ==================== SENSITIVE DATA DETECTOR ====================
class SensitiveDataDetector:
    def __init__(self, api_key_min_length: int = 32):
        self.patterns = {
            "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.IGNORECASE),
            "api_key": re.compile(r"\b[A-Za-z0-9\-_]{16,}\b"),
            "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            "password_field": re.compile(r"(?:password|passwd|pwd|pass)=([^&\s]+)", re.IGNORECASE),
            "cc_raw": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
            "basic_auth": re.compile(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE),
            "phone": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\d{10}|\d{3}[-.\s]\d{3}[-.\s]\d{4})\b")
        }
        self.api_key_min_length = api_key_min_length
        self.keywords = re.compile(r"\b(password|passwd|pwd|secret|token|apikey|api_key)\b", re.IGNORECASE)

    def _snippet(self, text: str, start: int, end: int, radius: int = 30) -> str:
        s = max(0, start - radius)
        e = min(len(text), end + radius)
        return text[s:e].replace("\r", " ").replace("\n", " ")

    def luhn_check(self, digits_only: str) -> bool:
        digits = [int(ch) for ch in digits_only if ch.isdigit()]
        if len(digits) < 13:
            return False
        total = 0
        reverse_digits = digits[::-1]
        for i, d in enumerate(reverse_digits):
            if i % 2 == 1:
                dbl = d * 2
                total += dbl - 9 if dbl > 9 else dbl
            else:
                total += d
        return total % 10 == 0

    def decode_basic_auth(self, token: str) -> str:
        try:
            decoded = base64.b64decode(token).decode('utf-8', errors='replace')
            return decoded
        except Exception:
            return ""

    def detect(self, text: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not text:
            return findings

        # Basic auth
        for m in self.patterns["basic_auth"].finditer(text):
            token = m.group(1)
            decoded = self.decode_basic_auth(token)
            ctx = self._snippet(text, m.start(), m.end())
            findings.append({
                "type": "basic_auth",
                "match": decoded or token,
                "context": ctx,
                "severity": "HIGH" if ":" in decoded else "MEDIUM",
                "mitigation": "Use HTTPS and token-based auth"
            })

        # Password fields
        for m in self.patterns["password_field"].finditer(text):
            pwd = m.group(1)
            ctx = self._snippet(text, m.start(), m.end())
            findings.append({
                "type": "password_field",
                "match": pwd,
                "context": ctx,
                "severity": "HIGH",
                "mitigation": "Send credentials only over TLS"
            })

        # Email addresses
        for m in self.patterns["email"].finditer(text):
            addr = m.group(0)
            ctx = self._snippet(text, m.start(), m.end())
            findings.append({
                "type": "email",
                "match": addr,
                "context": ctx,
                "severity": "LOW",
                "mitigation": "Inspect for linked credentials"
            })

        # API keys
        for m in self.patterns["api_key"].finditer(text):
            token = m.group(0)
            if len(token) >= self.api_key_min_length:
                ctx = self._snippet(text, m.start(), m.end())
                findings.append({
                    "type": "api_key",
                    "match": token,
                    "context": ctx,
                    "severity": "HIGH",
                    "mitigation": "Rotate key and use environment variables"
                })

        # SSNs
        for m in self.patterns["ssn"].finditer(text):
            ssn = m.group(0)
            ctx = self._snippet(text, m.start(), m.end())
            findings.append({
                "type": "ssn",
                "match": ssn,
                "context": ctx,
                "severity": "HIGH",
                "mitigation": "Treat as PII, encrypt data"
            })

        # Credit cards
        for m in self.patterns["cc_raw"].finditer(text):
            raw = m.group(0)
            digits = re.sub(r"[^0-9]", "", raw)
            if 13 <= len(digits) <= 19 and self.luhn_check(digits):
                ctx = self._snippet(text, m.start(), m.end())
                findings.append({
                    "type": "credit_card",
                    "match": digits,
                    "context": ctx,
                    "severity": "HIGH",
                    "mitigation": "Use tokenization and TLS"
                })

        # Phone numbers
        for m in self.patterns["phone"].finditer(text):
            phone = m.group(0)
            ctx = self._snippet(text, m.start(), m.end())
            findings.append({
                "type": "phone",
                "match": phone,
                "context": ctx,
                "severity": "LOW",
                "mitigation": "Avoid cleartext PII"
            })

        # Keywords
        for m in self.keywords.finditer(text):
            kw = m.group(0)
            ctx = self._snippet(text, m.start(), m.end())
            findings.append({
                "type": "keyword",
                "match": kw,
                "context": ctx,
                "severity": "LOW",
                "mitigation": "Inspect for credentials"
            })

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = (f["type"], str(f["match"]))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique


# ==================== FAST PACKET ANALYZER ====================
class FastNetworkAnalyzer:
    def __init__(self, alert_file: str = ALERT_FILE, verbose: bool = False):
        self.alerts = []
        self.alert_file = alert_file
        self.detector = SensitiveDataDetector()
        self.packet_count = 0
        self.alert_count = 0
        self.verbose = verbose
        self.stop_event = Event()
        self.session_start = datetime.datetime.now()
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0
        
        # NEW: Deduplication tracking
        self.seen_payloads = set()
        
        # Initialize alerts file with header
        self._init_alert_file()

    def _init_alert_file(self):
        """Initialize the alerts file with a header"""
        with open(self.alert_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write(" " * 20 + "NETSENTRY PACKET ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Scan Start Time    : {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Tool Version       : NetSentry v1.0\n")
            f.write(f"Report File        : {self.alert_file}\n")
            f.write("\n" + "=" * 80 + "\n\n")

    def guess_protocol(self, src_port, dst_port, payload_text):
        sp = str(src_port) if src_port else ""
        dp = str(dst_port) if dst_port else ""

        if "80" in (sp + dp):
            return "HTTP"
        if "21" in (sp + dp):
            return "FTP"
        if "25" in (sp + dp) or "587" in (sp + dp):
            return "SMTP"
        if "443" in (sp + dp):
            return "HTTPS"
        if "22" in (sp + dp):
            return "SSH"

        if payload_text:
            if "HTTP/" in payload_text or "POST " in payload_text or "GET " in payload_text:
                return "HTTP"
            if "EHLO" in payload_text or "MAIL FROM" in payload_text:
                return "SMTP"

        return "UNKNOWN"

    def process_packet(self, pkt):
        try:
            self.packet_count += 1
            
            ts = datetime.datetime.fromtimestamp(float(pkt.time))
            
            src = pkt[IP].src if pkt.haslayer(IP) else "unknown"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "unknown"
            
            src_port = None
            dst_port = None
            if pkt.haslayer(TCP):
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

            payload_text = None
            if pkt.haslayer(Raw):
                raw_bytes = pkt[Raw].load
                try:
                    payload_text = raw_bytes.decode("utf-8", errors="replace")
                except Exception:
                    payload_text = str(raw_bytes)

            if payload_text:
                # FILTER 1: Skip HTML pages (form templates)
                if payload_text.strip().startswith('<!DOCTYPE') or \
                   payload_text.strip().startswith('<html'):
                    if self.verbose:
                        print(f"[DEBUG] Skipping HTML page response")
                    return
                
                # FILTER 2: Skip HTTP responses that just echo data
                if 'HTTP/1.1 200' in payload_text[:50] and 'POST' not in payload_text:
                    if self.verbose:
                        print(f"[DEBUG] Skipping HTTP 200 response")
                    return
                
                # FILTER 3: Deduplication - hash the payload
                payload_hash = hashlib.md5(payload_text.encode()).hexdigest()
                
                if payload_hash in self.seen_payloads:
                    if self.verbose:
                        print(f"[DEBUG] Skipping duplicate payload (hash: {payload_hash[:8]}...)")
                    return
                
                self.seen_payloads.add(payload_hash)
                
                proto = self.guess_protocol(src_port, dst_port, payload_text)
                findings = self.detector.detect(payload_text)
                
                if findings:
                    self.alert_count += 1
                    
                    # Determine highest severity
                    severities = [f['severity'] for f in findings]
                    if 'HIGH' in severities:
                        highest_severity = 'HIGH'
                        self.high_count += 1
                    elif 'MEDIUM' in severities:
                        highest_severity = 'MEDIUM'
                        self.medium_count += 1
                    else:
                        highest_severity = 'LOW'
                        self.low_count += 1
                    
                    # Save alert to file
                    self.save_alert(self.alert_count, ts, src, src_port, dst, dst_port, 
                                   proto, findings, payload_text, highest_severity)
                    
                    if self.verbose:
                        self._print_alert_console(self.alert_count, ts, src, src_port, 
                                                 dst, dst_port, proto, findings, highest_severity)
            
            if self.verbose and self.packet_count % 100 == 0:
                print(f"[*] Packets processed: {self.packet_count} | Alerts: {self.alert_count}")
                
        except Exception as e:
            if self.verbose:
                print(f"[!] Error processing packet: {e}")

    def _print_alert_console(self, alert_id, ts, src, src_port, dst, dst_port, 
                            proto, findings, severity):
        """Print alert to console in verbose mode"""
        print(f"\n{'='*70}")
        print(f"[ALERT #{alert_id}] {severity} SEVERITY")
        print(f"{'='*70}")
        print(f"Timestamp          : {ts.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Source             : {src}:{src_port}")
        print(f"Destination        : {dst}:{dst_port}")
        print(f"Protocol           : {proto}")
        print(f"\nDETECTED THREATS ({len(findings)} findings):\n")
        
        for i, f in enumerate(findings, 1):
            threat_type = f['type'].replace('_', ' ').upper()
            print(f"  {i}. {threat_type} [{f['severity']}]")
            print(f"     Detected Value   : {f['match'][:60]}")
            print(f"     Context          : {f['context'][:60]}...")
            print(f"     Recommendation   : {f['mitigation']}\n")
        
        print(f"{'='*70}\n")

    def save_alert(self, alert_id, ts, src, src_port, dst, dst_port, 
                   proto, findings, payload_text, severity):
        """Save alert to text file"""
        try:
            with open(self.alert_file, 'a') as f:
                # Alert header
                f.write("\n" + "=" * 80 + "\n")
                f.write(f"[ALERT #{alert_id}] - {severity} SEVERITY\n")
                f.write("=" * 80 + "\n")
                f.write(f"Timestamp          : {ts.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Source             : {src}:{src_port}\n")
                f.write(f"Destination        : {dst}:{dst_port}\n")
                f.write(f"Protocol           : {proto}\n")
                f.write(f"\nDETECTED THREATS ({len(findings)} findings):\n\n")
                
                # Findings
                for i, finding in enumerate(findings, 1):
                    threat_type = finding['type'].replace('_', ' ').upper()
                    f.write(f"  {i}. {threat_type} [{finding['severity']}]\n")
                    f.write(f"     Detected Value   : {finding['match']}\n")
                    f.write(f"     Context          : {finding['context']}\n")
                    f.write(f"     Recommendation   : {finding['mitigation']}\n\n")
                
                # Payload preview
                preview = payload_text[:300] if len(payload_text) > 300 else payload_text
                f.write(f"Payload Preview:\n")
                f.write("-" * 80 + "\n")
                for line in preview.split('\n')[:10]:  # First 10 lines
                    f.write(f"{line}\n")
                if len(payload_text) > 300:
                    f.write("... (truncated)\n")
                f.write("-" * 80 + "\n\n")
                
        except Exception as e:
            print(f"[!] Error saving alert: {e}")

    def finalize_report(self):
        """Add final statistics to the report"""
        try:
            session_end = datetime.datetime.now()
            duration = session_end - self.session_start
            
            # Calculate duration in human-readable format
            hours, remainder = divmod(int(duration.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            duration_str = f"{hours} hour{'s' if hours != 1 else ''} {minutes} minute{'s' if minutes != 1 else ''} {seconds} second{'s' if seconds != 1 else ''}"
            
            with open(self.alert_file, 'a') as f:
                f.write("\n" + "=" * 80 + "\n")
                f.write(" " * 30 + "SCAN SUMMARY\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Scan Start Time              : {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Scan End Time                : {session_end.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Duration               : {duration_str}\n")
                f.write(f"Total Packets Analyzed       : {self.packet_count:,}\n")
                f.write(f"Total Alerts Generated       : {self.alert_count:,}\n")
                f.write(f"High Severity Alerts         : {self.high_count}\n")
                f.write(f"Medium Severity Alerts       : {self.medium_count}\n")
                f.write(f"Low Severity Alerts          : {self.low_count}\n")
                f.write("\n" + "=" * 80 + "\n")
                f.write(" " * 25 + "END OF REPORT\n")
                f.write("=" * 80 + "\n")
                
        except Exception as e:
            print(f"[!] Error finalizing report: {e}")

    def start_live_capture(self, interface: str, packet_count: int = 0, 
                          bpf_filter: str = None):
        """Fast live packet capture using Scapy's sniff"""
        print(f"[+] Starting live capture on {interface}")
        if bpf_filter:
            print(f"[+] Filter: {bpf_filter}")
        print(f"[+] Capturing {'unlimited' if packet_count == 0 else packet_count} packets...")
        print(f"[+] Alerts will be saved to: {self.alert_file}")
        print("[+] Press Ctrl+C to stop\n")
        
        try:
            sniff(
                iface=interface,
                prn=self.process_packet,
                count=packet_count if packet_count > 0 else 0,
                filter=bpf_filter,
                store=False  # Don't store packets in memory for speed
            )
        except KeyboardInterrupt:
            print(f"\n[+] Capture stopped by user")
        except Exception as e:
            print(f"[!] Capture error: {e}")
        
        # Finalize the report
        self.finalize_report()
        
        print(f"\n{'='*70}")
        print(f"SCAN SUMMARY")
        print(f"{'='*70}")
        print(f"Total packets analyzed      : {self.packet_count:,}")
        print(f"Total alerts generated      : {self.alert_count}")
        print(f"  High Severity             : {self.high_count}")
        print(f"  Medium Severity           : {self.medium_count}")
        print(f"  Low Severity              : {self.low_count}")
        print(f"Report saved to             : {self.alert_file}")
        print(f"{'='*70}\n")


# ==================== CLI INTERFACE ====================
def check_privileges():
    """Check if running with sufficient privileges for packet capture"""
    if os.geteuid() != 0:
        print("[!] Warning: Not running as root. You may need sudo for packet capture.")
        return False
    return True

def list_interfaces():
    """List available network interfaces"""
    try:
        result = subprocess.run(['ip', 'link', 'show'], 
                              capture_output=True, text=True, check=False)
        if result.returncode == 0:
            print("[+] Available interfaces:")
            lines = result.stdout.split('\n')
            for line in lines:
                if ':' in line and '@' not in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        iface = parts[1].strip()
                        if iface:
                            print(f"    - {iface}")
        else:
            print("[!] Could not list interfaces. Using default.")
    except Exception as e:
        print(f"[!] Error listing interfaces: {e}")

def show_banner():
    banner = """
╔═══════════════════════════════════════════════════════╗
║              NetSentry - Packet Analysis Tool             ║
║          Capture • Analyze • Detect • Alert               ║
╚═══════════════════════════════════════════════════════╝
"""
    print(banner)

def main():
    show_banner()
    
    parser = argparse.ArgumentParser(
        description='NetSentry - Network Packet Analysis Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Capture 1000 packets on eth0 (HTTP/FTP/SMTP only)
  sudo python3 netsentry.py -i eth0 -c 1000 -f "tcp port 80 or port 21 or port 25"
  
  # Live capture with verbose output
  sudo python3 netsentry.py -i wlan0 -v
  
  # Capture only HTTP traffic
  sudo python3 netsentry.py -i eth0 -f "tcp port 80"
  
  # List available interfaces
  python3 netsentry.py --list-interfaces
        """
    )
    
    parser.add_argument('-i', '--interface', 
                       default=DEFAULT_INTERFACE,
                       help=f'Network interface (default: {DEFAULT_INTERFACE})')
    
    parser.add_argument('-c', '--count', 
                       type=int, 
                       default=0,
                       help='Number of packets to capture (0 = unlimited)')
    
    parser.add_argument('-f', '--filter', 
                       default=None,
                       help='BPF filter (e.g., "tcp port 80 or port 443")')
    
    parser.add_argument('-o', '--output', 
                       default=ALERT_FILE,
                       help=f'Alert output file (default: {ALERT_FILE})')
    
    parser.add_argument('-v', '--verbose', 
                       action='store_true',
                       help='Verbose output (show alerts in real-time)')
    
    parser.add_argument('--list-interfaces', 
                       action='store_true',
                       help='List available network interfaces')
    
    args = parser.parse_args()
    
    # List interfaces and exit
    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)
    
    # Check privileges
    check_privileges()
    
    # Create analyzer
    analyzer = FastNetworkAnalyzer(
        alert_file=args.output,
        verbose=args.verbose
    )
    
    # Start capture
    try:
        analyzer.start_live_capture(
            interface=args.interface,
            packet_count=args.count,
            bpf_filter=args.filter
        )
    except PermissionError:
        print("[!] Permission denied. Try running with sudo:")
        print(f"    sudo python3 {sys.argv[0]} {' '.join(sys.argv[1:])}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
