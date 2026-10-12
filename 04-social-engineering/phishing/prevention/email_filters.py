#!/usr/bin/env python3
"""
Email Filters for Phishing Prevention

This script configures email filtering rules for various mail servers
to block phishing and spam emails.
"""

import os
import sys
import re
import json
import argparse
import subprocess
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

class EmailFilterConfig:
    """
    Email Filter Configuration System
    """
    
    def __init__(self):
        self.filters = {
            'spf': [],
            'dkim': [],
            'dmarc': [],
            'content': [],
            'attachment': [],
            'header': [],
            'rate_limit': []
        }
        
    def generate_postfix_filters(self, domain):
        """Generate Postfix filter rules"""
        filters = f"""
# Postfix Filter Rules for {domain}
# Generated on {datetime.now()}

# ============================================
# HELO/EHLO Restrictions
# ============================================
smtpd_helo_required = yes
smtpd_helo_restrictions = 
    permit_mynetworks,
    reject_invalid_helo_hostname,
    reject_non_fqdn_helo_hostname,
    reject_unknown_helo_hostname

# ============================================
# Sender Restrictions
# ============================================
smtpd_sender_restrictions = 
    permit_mynetworks,
    reject_non_fqdn_sender,
    reject_unknown_sender_domain,
    reject_authenticated_sender_login_mismatch,
    reject_sender_login_mismatch

# ============================================
# Recipient Restrictions
# ============================================
smtpd_recipient_restrictions = 
    permit_mynetworks,
    reject_unauth_destination,
    reject_non_fqdn_recipient,
    reject_unknown_recipient_domain,
    check_policy_service unix:private/policy-spf

# ============================================
# Content Filtering
# ============================================
# Enable content filter
content_filter = smtp-amavis:[127.0.0.1]:10024

# ============================================
# Rate Limiting
# ============================================
# Limit connections per client
smtpd_client_connection_rate_limit = 10
smtpd_client_message_rate_limit = 100
smtpd_client_recipient_rate_limit = 100

# ============================================
# SPF Configuration
# ============================================
# Install postfix-policyd-spf-perl
policy-spf_time_limit = 3600
smtpd_recipient_restrictions += 
    check_policy_service unix:private/policyd-spf

# ============================================
# RBL Filters
# ============================================
smtpd_recipient_restrictions += 
    reject_rbl_client zen.spamhaus.org,
    reject_rbl_client bl.spamcop.net,
    reject_rbl_client cbl.abuseat.org,
    reject_rbl_client dnsbl.sorbs.net

# ============================================
# Custom Header Checks
# ============================================
header_checks = regexp:/etc/postfix/header_checks

# /etc/postfix/header_checks content:
/^Subject:.*\b(urgent|verify|account|suspended)\b/i REJECT Suspicious subject
/^From:.*@(?!{domain})/i REJECT Unauthorized sender domain
"""
        return filters
    
    def generate_header_checks(self):
        """Generate Postfix header check rules"""
        rules = r"""#
# Postfix header check rules
# Place in /etc/postfix/header_checks
#

# ============================================
# Subject line patterns
# ============================================
/^Subject:.*\burrent\b/i                   REJECT Spam keyword
/^Subject:.*\bimmediate action\b/i         REJECT Spam keyword
/^Subject:.*\baccount.*suspended\b/i       REJECT Spam keyword
/^Subject:.*\bsecurity alert\b/i           REJECT Spam keyword
/^Subject:.*\bverify.*account\b/i          REJECT Spam keyword
/^Subject:.*\bunusual activity\b/i         REJECT Spam keyword
/^Subject:.*\bclick here\b/i                REJECT Spam keyword
/^Subject:.*\bwin.*prize\b/i                REJECT Spam keyword
/^Subject:.*\blottery\b/i                   REJECT Spam keyword
/^Subject:.*\binheritance\b/i               REJECT Spam keyword
/^Subject:.*\bwire transfer\b/i             REJECT Spam keyword
/^Subject:.*\bgift card\b/i                 REJECT Spam keyword
/^Subject:.*\bitunes\b/i                     REJECT Spam keyword
/^Subject:.*\bamazon\b/i                     REJECT Spam keyword
/^Subject:.*\bpaypal\b/i                     REJECT Spam keyword
/^Subject:.*\bnetflix\b/i                    REJECT Spam keyword
/^Subject:.*\bmicrosoft\b/i                  REJECT Spam keyword
/^Subject:.*\bapple\b/i                      REJECT Spam keyword

# ============================================
# From header patterns
# ============================================
/^From:.*@.*\.tk\b/i                        REJECT Suspicious TLD
/^From:.*@.*\.ml\b/i                        REJECT Suspicious TLD
/^From:.*@.*\.ga\b/i                        REJECT Suspicious TLD
/^From:.*@.*\.cf\b/i                        REJECT Suspicious TLD
/^From:.*@.*\.gq\b/i                        REJECT Suspicious TLD
/^From:.*@.*\.xyz\b/i                       REJECT Suspicious TLD
/^From:.*@.*\.top\b/i                       REJECT Suspicious TLD
/^From:.*@.*\.win\b/i                       REJECT Suspicious TLD
/^From:.*@.*\.bid\b/i                       REJECT Suspicious TLD
/^From:.*@.*\.trade\b/i                     REJECT Suspicious TLD

# ============================================
# Spoofed domains
# ============================================
/^From:.*@.*paypa[li]\.com?/i               REJECT Possible PayPal spoof
/^From:.*@.*paypa[li]\.net?/i               REJECT Possible PayPal spoof
/^From:.*@.*amaz[o0]n\.[a-z]+/i             REJECT Possible Amazon spoof
/^From:.*@.*micr0s0ft\.[a-z]+/i             REJECT Possible Microsoft spoof
/^From:.*@.*g00gle\.[a-z]+/i                REJECT Possible Google spoof
/^From:.*@.*faceb00k\.[a-z]+/i              REJECT Possible Facebook spoof
/^From:.*@.*appIe\.[a-z]+/i                 REJECT Possible Apple spoof
/^From:.*@.*netfl1x\.[a-z]+/i               REJECT Possible Netflix spoof

# ============================================
# Attachment warnings
# ============================================
/^Content-Type:.*name=.*\.exe/i              WARNING Executable attachment
/^Content-Type:.*name=.*\.scr/i              WARNING Screensaver attachment
/^Content-Type:.*name=.*\.bat/i              WARNING Batch file attachment
/^Content-Type:.*name=.*\.cmd/i              WARNING Command file attachment
/^Content-Type:.*name=.*\.vbs/i              WARNING VBScript attachment
/^Content-Type:.*name=.*\.js/i               WARNING JavaScript attachment
/^Content-Type:.*name=.*\.jar/i              WARNING Java attachment
/^Content-Type:.*name=.*\.docm/i             WARNING Macro-enabled document
/^Content-Type:.*name=.*\.xlsm/i             WARNING Macro-enabled spreadsheet
/^Content-Type:.*name=.*\.pptm/i             WARNING Macro-enabled presentation
"""
        return rules
    
    def generate_spf_record(self, domain, ip_ranges=None):
        """Generate SPF record"""
        if ip_ranges is None:
            ip_ranges = ['include:_spf.google.com']
        
        spf = f"v=spf1 {' '.join(ip_ranges)} -all"
        return spf
    
    def generate_dkim_record(self, domain, selector='default', key_length=2048):
        """Generate DKIM record"""
        # Note: Actual key generation would be done separately
        dkim = f"v=DKIM1; h=sha256; k=rsa; p=YOUR_PUBLIC_KEY_HERE"
        return dkim
    
    def generate_dmarc_record(self, domain, policy='reject'):
        """Generate DMARC record"""
        dmarc = f"v=DMARC1; p={policy}; rua=mailto:dmarc@{domain}; ruf=mailto:dmarc@{domain}; fo=1; pct=100"
        return dmarc
    
    def generate_exim_filters(self):
        """Generate Exim filter rules"""
        filters = f"""
# Exim Filter Rules
# Generated on {datetime.now()}

# ============================================
# ACL before MAIL
# ============================================
acl_check_mail:
  deny message = HELO required before MAIL
       condition = $sender_helo_name is empty

# ============================================
# ACL before RCPT
# ============================================
acl_check_rcpt:
  accept hosts = :
  
  deny message = Rejected because $sender_host_address is in a black list at $dnslist_domain\n$dnslist_text
       dnslists = zen.spamhaus.org : bl.spamcop.net : dnsbl.sorbs.net
  
  warn message = X-Spam-Score: $spam_score_int
       spam = nobody/defer_ok

  # Rate limiting
  defer message = Too many connections from this IP
        ratelimit = 20 / 1h / per_conn / strict

# ============================================
# Router for spam filtering
# ============================================
spamcheck:
  driver = accept
  condition = ${{if >{{$spam_score_int}}{{50}}{{1}}{{0}}}}
  transport = spam_filter

# ============================================
# Transport for spam
# ============================================
spam_filter:
  driver = pipe
  command = /usr/bin/spamc -f -u $local_part@$domain
  return_output
"""
        return filters
    
    def generate_sieve_filters(self):
        """Generate Sieve filter rules (Dovecot)"""
        filters = f"""
# Sieve Filter Rules
# Generated on {datetime.now()}

require ["fileinto", "mailbox", "envelope", "regex", "variables"];

# ============================================
# Spam filtering
# ============================================
if anyof (
    header :contains "X-Spam-Flag" "YES",
    header :contains "X-Spam-Status" "Yes"
) {{
    fileinto "Spam";
    stop;
}}

# ============================================
# Suspicious sender domains
# ============================================
if address :domain :contains "From" [
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".win", ".bid", ".trade"
] {{
    fileinto "Spam/SuspiciousDomains";
    stop;
}}

# ============================================
# Urgent subject patterns
# ============================================
if header :regex "Subject" [
    ".*urgent.*",
    ".*immediate action.*",
    ".*account.*suspended.*",
    ".*security alert.*",
    ".*verify.*account.*",
    ".*unusual activity.*"
] {{
    fileinto "PotentialPhishing";
    stop;
}}

# ============================================
# Suspicious attachments
# ============================================
if anyof (
    header :contains "Content-Type" "name=.*\\.exe",
    header :contains "Content-Type" "name=.*\\.scr",
    header :contains "Content-Type" "name=.*\\.bat",
    header :contains "Content-Type" "name=.*\\.vbs",
    header :contains "Content-Type" "name=.*\\.js"
) {{
    fileinto "Quarantine/SuspiciousAttachments";
    stop;
}}

# ============================================
# Spoofed domains
# ============================================
if address :domain :matches "From" "*" {{
    set "domain" "${{1}}";
    
    # Check for common spoofs
    if string "${{domain}}" contains "paypa" {{
        if not string "${{domain}}" is "paypal.com" {{
            fileinto "Spam/SpoofedDomains";
            stop;
        }}
    }}
    
    if string "${{domain}}" contains "amaz" {{
        if not string "${{domain}}" is "amazon.com" {{
            fileinto "Spam/SpoofedDomains";
            stop;
        }}
    }}
}}

# ============================================
# Bulk emails folder
# ============================================
if anyof (
    header :contains "List-Unsubscribe" "",
    header :contains "Precedence" "bulk",
    header :contains "Precedence" "list"
) {{
    fileinto "Bulk";
    stop;
}}

# ============================================
# Newsletter folder
# ============================================
if anyof (
    header :contains "Subject" "newsletter",
    header :contains "Subject" "weekly digest",
    header :contains "X-Mailer" "MailChimp",
    header :contains "X-Mailer" "ConstantContact"
) {{
    fileinto "Newsletters";
    stop;
}}

# ============================================
# Notifications folder
# ============================================
if anyof (
    envelope :contains "From" "noreply@",
    envelope :contains "From" "no-reply@",
    envelope :contains "From" "notifications@"
) {{
    fileinto "Notifications";
    stop;
}}

# ============================================
# Default action
# ============================================
# Keep in inbox
keep;
"""
        return filters
    
    def generate_rspamd_config(self):
        """Generate Rspamd configuration"""
        config = f"""
# Rspamd Configuration
# Generated on {datetime.now()}

# ============================================
# Main configuration
# ============================================
worker {{
    type = "normal";
    bind_socket = "*:11333";
    bind_socket = "localhost:11334";
    count = 4;
}}

worker {{
    type = "controller";
    bind_socket = "localhost:11334";
    count = 1;
    secure_ip = "127.0.0.1";
    secure_ip = "::1";
    password = "admin";
}}

# ============================================
# Modules
# ============================================
surbl {{
    enabled = true;
    symbols = {{
        "SURBL_BLOCKED"
        "SURBL_BLOCKED" = {{
            weight = 5.0;
            description = "URL is listed in SURBL blocklist";
        }};
    }}
}}

spamassassin {{
    enabled = true;
    spamd_host = "localhost";
    spamd_port = 783;
    timeout = 5.0;
}}

dkim {{
    enabled = true;
    allow_username_mismatch = false;
    symbol_ok = "DKIM_SIGNED";
    symbol_allow = "DKIM_ALLOW";
    symbol_reject = "DKIM_REJECT";
    symbol_tempfail = "DKIM_TEMPFAIL";
}}

spf {{
    enabled = true;
    symbol_pass = "SPF_ALLOW";
    symbol_fail = "SPF_DENY";
    symbol_softfail = "SPF_SOFTFAIL";
    symbol_neutral = "SPF_NEUTRAL";
    symbol_none = "SPF_NA";
    symbol_permerror = "SPF_PERMERROR";
    symbol_temperror = "SPF_TEMPFAIL";
}}

dmarc {{
    enabled = true;
    symbol_pass = "DMARC_POLICY_ALLOW";
    symbol_fail = "DMARC_POLICY_REJECT";
    symbol_quarantine = "DMARC_POLICY_QUARANTINE";
}}

# ============================================
# Rate limiting
# ============================================
ratelimit {{
    enabled = true;
    limits = {{
        # Limit per IP
        ip = {{
            burst = 100;
            rate = "50 / 1m";
        }}
        # Limit per user
        user = {{
            burst = 200;
            rate = "100 / 1m";
        }}
    }}
    symbols = {{
        "RATELIMITED" = {{
            weight = 3.0;
            description = "Message rate limited";
        }}
    }}
}}

# ============================================
# Phishing detection
# ============================================
phishing {{
    enabled = true;
    action = "reject";
    symbols = {{
        "PHISHING" = {{
            weight = 10.0;
            description = "Phishing attempt detected";
        }}
    }}
}}

# ============================================
# Attachments
# ============================================
mime_types {{
    enabled = true;
    bad_extensions = [
        ".exe", ".scr", ".bat", ".cmd", ".vbs",
        ".js", ".jar", ".msi", ".ps1", ".dll"
    ];
    symbols = {{
        "BAD_ATTACHMENT" = {{
            weight = 5.0;
            description = "Suspicious attachment type";
        }}
    }}
}}
"""
        return config
    
    def generate_spamassassin_rules(self):
        """Generate SpamAssassin rules"""
        rules = rf"""
# SpamAssassin Rules for Phishing Detection
# Generated on {datetime.now()}

# ============================================
# Header rules
# ============================================
header PHISHING_URGENT Subject =~ /(urgent|immediate|asap|warning)/i
describe PHISHING_URGENT Contains urgent language
score PHISHING_URGENT 1.5

header PHISHING_VERIFY Subject =~ /(verify|confirm|validate|update)/i
describe PHISHING_VERIFY Asks for verification
score PHISHING_VERIFY 1.5

header PHISHING_ACCOUNT Subject =~ /(account|paypal|bank|amazon)/i
describe PHISHING_ACCOUNT References account/financial
score PHISHING_ACCOUNT 1.0

# ============================================
# From rules
# ============================================
header PHISHING_SPOOF From =~ /@(paypa[li]|amaz[o0]n|micr0s0ft|g00gle)/i
describe PHISHING_SPOOF Spoofed domain name
score PHISHING_SPOOF 3.0

header PHISHING_FREE_TLD From =~ /@.*\.(tk|ml|ga|cf|gq|xyz|top|win)/i
describe PHISHING_FREE_TLD Suspicious free TLD
score PHISHING_FREE_TLD 2.0

# ============================================
# Body rules
# ============================================
body PHISHING_LINK eval:check_phishing_links()
describe PHISHING_LINK Contains suspicious links
score PHISHING_LINK 2.5

body PHISHING_PASSWORD eval:check_password_request()
describe PHISHING_PASSWORD Requests password
score PHISHING_PASSWORD 3.0

body PHISHING_CREDIT eval:check_credit_request()
describe PHISHING_CREDIT Requests credit card
score PHISHING_CREDIT 3.0

body PHISHING_HTML eval:check_html_forms()
describe PHISHING_HTML Contains HTML form
score PHISHING_HTML 1.0

# ============================================
# URI rules
# ============================================
uri PHISHING_IP eval:check_ip_url()
describe PHISHING_IP URL uses IP address
score PHISHING_IP 2.0

uri PHISHING_SHORTENER eval:check_url_shortener()
describe PHISHING_SHORTENER Uses URL shortener
score PHISHING_SHORTENER 1.5

uri PHISHING_SUSPICIOUS_TLD eval:check_suspicious_tld()
describe PHISHING_SUSPICIOUS_TLD Suspicious TLD in URL
score PHISHING_SUSPICIOUS_TLD 2.0

# ============================================
# Attachment rules
# ============================================
header PHISHING_EXE Content-Type =~ /name=.*\.exe/i
describe PHISHING_EXE Contains executable attachment
score PHISHING_EXE 4.0

header PHISHING_ZIP Content-Type =~ /name=.*\.zip/i
describe PHISHING_ZIP Contains ZIP attachment
score PHISHING_ZIP 2.0

header PHISHING_DOCM Content-Type =~ /name=.*\.(docm|xlsm|pptm)/i
describe PHISHING_DOCM Contains macro-enabled document
score PHISHING_DOCM 3.0

# ============================================
# Combined rules
# ============================================
meta PHISHING_HIGH_SCORE (PHISHING_URGENT + PHISHING_VERIFY + PHISHING_ACCOUNT > 3)
describe PHISHING_HIGH_SCORE High phishing probability
score PHISHING_HIGH_SCORE 5.0

meta PHISHING_CRITICAL (PHISHING_SPOOF && (PHISHING_PASSWORD || PHISHING_CREDIT))
describe PHISHING_CRITICAL Critical phishing indicators
score PHISHING_CRITICAL 8.0

# ============================================
# Plugin functions
# ============================================
loadplugin Mail::SpamAssassin::Plugin::URIDNSBL
loadplugin Mail::SpamAssassin::Plugin::Phishing

# ============================================
# Whitelist
# ============================================
whitelist_from *@trusted-domain.com
whitelist_from *@partner-company.com

# ============================================
# Blacklist
# ============================================
blacklist_from *@suspicious-domain.tk
blacklist_from *@spammer.com
"""
        return rules
    
    def generate_postgrey_config(self):
        """Generate Postgrey configuration for greylisting"""
        config = f"""
# Postgrey Configuration
# Generated on {datetime.now()}

# ============================================
# Main configuration
# ============================================
OPTIONS="--inet=127.0.0.1:10023 --delay=300 --max-age=35"

# ============================================
# Whitelist clients
# ============================================
# /etc/postgrey/whitelist_clients
192.168.0.0/16
10.0.0.0/8
172.16.0.0/12
127.0.0.0/8
::1

# ============================================
# Whitelist recipients
# ============================================
# /etc/postgrey/whitelist_recipients
postmaster@*
abuse@*
mailer-daemon@*

# ============================================
# Auto-whitelist
# ============================================
AUTOWHITELIST_FILE="/var/lib/postgrey/autowhitelist.db"
AUTOWHITELIST_WINDOW=30
"""
        return config
    
    def generate_opendkim_config(self):
        """Generate OpenDKIM configuration"""
        config = f"""
# OpenDKIM Configuration
# Generated on {datetime.now()}

# ============================================
# Base settings
# ============================================
Syslog                  yes
SyslogSuccess           yes
LogWhy                  yes

UserID                  opendkim:opendkim
UMask                   002

Canonicalization        relaxed/simple
Mode                    sv
SubDomains              no

# ============================================
# Socket
# ============================================
Socket                  inet:8891@localhost

# ============================================
# Signing table
# ============================================
SigningTable            refile:/etc/opendkim/signing.table
KeyTable                refile:/etc/opendkim/key.table
KeyTable                refile:/etc/opendkim/key.table

# ============================================
# Internal hosts
# ============================================
InternalHosts           /etc/opendkim/trusted.hosts

# ============================================
# External ignore list
# ============================================
ExternalIgnoreList      refile:/etc/opendkim/trusted.hosts

# ============================================
# Oversigning
# ============================================
OversignHeaders         From
OversignHeaders         Reply-To
OversignHeaders         Subject
OversignHeaders         Date
OversignHeaders         To
OversignHeaders         Cc
OversignHeaders         Message-ID
OversignHeaders         Resent-Date
OversignHeaders         Resent-From
OversignHeaders         Resent-To
OversignHeaders         Resent-Cc
OversignHeaders         In-Reply-To
OversignHeaders         References
OversignHeaders         List-Id
OversignHeaders         List-Help
OversignHeaders         List-Unsubscribe
OversignHeaders         List-Subscribe
OversignHeaders         List-Post
OversignHeaders         List-Owner
OversignHeaders         List-Archive

# ============================================
# Statistics
# ============================================
Statistics              /var/log/opendkim/opendkim.stats
"""
        return config
    
    def generate_domain_config(self, domain):
        """Generate complete domain email security configuration"""
        config = f"""
# Domain Email Security Configuration for {domain}
# Generated on {datetime.now()}

# ============================================
# DNS Records
# ============================================

# SPF Record (TXT)
{domain}. IN TXT "{self.generate_spf_record(domain)}"

# DKIM Record (TXT)
default._domainkey.{domain}. IN TXT "{self.generate_dkim_record(domain)}"

# DMARC Record (TXT)
_dmarc.{domain}. IN TXT "{self.generate_dmarc_record(domain)}"

# MX Records
{domain}. IN MX 10 mail.{domain}.

# ============================================
# MTA-STS Policy
# ============================================
# File: .well-known/mta-sts.txt
# Host: mta-sts.{domain}
---
version: STSv1
mode: enforce
mx: mail.{domain}
max_age: 604800

# ============================================
# TLS Reporting
# ============================================
# TLSRPT Record (TXT)
_smtp._tls.{domain}. IN TXT "v=TLSRPTv1; rua=mailto:tls-reports@{domain}"

# ============================================
# BIMI Record (optional)
# ============================================
default._bimi.{domain}. IN TXT "v=BIMI1; l=https://{domain}/logo.svg; a=https://{domain}/assertion.pem"

# ============================================
# Mail Server Configuration Checklist
# ============================================

## Required
□ SPF record published
□ DKIM keys generated and published
□ DMARC policy configured (start with p=none, move to p=quarantine, then p=reject)
□ MX records configured
□ Reverse DNS (PTR) configured for mail server IP

## Recommended
□ MTA-STS configured
□ TLS reporting enabled
□ BIMI configured (for brand protection)
□ ARC configured for email forwarding
□ Greylisting enabled
□ Rate limiting configured

## Optional
□ DANE TLSA records
□ SMTP TLS reporting
□ OpenPGP/ S/MIME for encryption
"""
        return config

def main():
    parser = argparse.ArgumentParser(description='Email Filter Configuration Generator')
    parser.add_argument('--domain', help='Domain to generate configuration for')
    parser.add_argument('--type', choices=['postfix', 'exim', 'sieve', 'rspamd', 'spamassassin', 'all'],
                       default='all', help='Type of configuration to generate')
    parser.add_argument('--output-dir', default='./email_filters', help='Output directory')
    
    args = parser.parse_args()
    
    print(f"""
    {Fore.CYAN}╔═══════════════════════════════════════╗
    ║     Email Filter Config Generator     ║
    ║       Phishing Prevention Tool        ║
    ║       FOR EDUCATIONAL USE ONLY        ║
    ╚═══════════════════════════════════════╝{Style.RESET_ALL}
    """)
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    config = EmailFilterConfig()
    
    if args.type in ['postfix', 'all']:
        print(f"{Fore.CYAN}[*] Generating Postfix configuration...{Style.RESET_ALL}")
        with open(f"{args.output_dir}/postfix_main.cf", 'w') as f:
            f.write(config.generate_postfix_filters(args.domain or 'example.com'))
        
        with open(f"{args.output_dir}/header_checks", 'w') as f:
            f.write(config.generate_header_checks())
        print(f"{Fore.GREEN}  [✓] Postfix configuration generated{Style.RESET_ALL}")
    
    if args.type in ['exim', 'all']:
        print(f"{Fore.CYAN}[*] Generating Exim configuration...{Style.RESET_ALL}")
        with open(f"{args.output_dir}/exim_filters.conf", 'w') as f:
            f.write(config.generate_exim_filters())
        print(f"{Fore.GREEN}  [✓] Exim configuration generated{Style.RESET_ALL}")
    
    if args.type in ['sieve', 'all']:
        print(f"{Fore.CYAN}[*] Generating Sieve filters...{Style.RESET_ALL}")
        with open(f"{args.output_dir}/sieve_filters.sieve", 'w') as f:
            f.write(config.generate_sieve_filters())
        print(f"{Fore.GREEN}  [✓] Sieve filters generated{Style.RESET_ALL}")
    
    if args.type in ['rspamd', 'all']:
        print(f"{Fore.CYAN}[*] Generating Rspamd configuration...{Style.RESET_ALL}")
        with open(f"{args.output_dir}/rspamd.conf", 'w') as f:
            f.write(config.generate_rspamd_config())
        print(f"{Fore.GREEN}  [✓] Rspamd configuration generated{Style.RESET_ALL}")
    
    if args.type in ['spamassassin', 'all']:
        print(f"{Fore.CYAN}[*] Generating SpamAssassin rules...{Style.RESET_ALL}")
        with open(f"{args.output_dir}/spamassassin_rules.cf", 'w') as f:
            f.write(config.generate_spamassassin_rules())
        print(f"{Fore.GREEN}  [✓] SpamAssassin rules generated{Style.RESET_ALL}")
    
    if args.domain:
        print(f"{Fore.CYAN}[*] Generating domain configuration for {args.domain}...{Style.RESET_ALL}")
        with open(f"{args.output_dir}/{args.domain}_config.txt", 'w') as f:
            f.write(config.generate_domain_config(args.domain))
        print(f"{Fore.GREEN}  [✓] Domain configuration generated{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}[✓] All configurations saved to {args.output_dir}/{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}Next steps:{Style.RESET_ALL}")
    print("1. Review generated configurations")
    print("2. Test in staging environment")
    print("3. Deploy to production gradually")
    print("4. Monitor logs for false positives")
    print("5. Adjust thresholds based on traffic patterns")

if __name__ == "__main__":
    main()
