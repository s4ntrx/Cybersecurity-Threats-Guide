
### pretexting/detection/social_engineering_detector.py

#!/usr/bin/env python3
"""
Social Engineering Detector
This script analyzes phone calls, text messages, and in-person interactions
for social engineering indicators.
"""

import re
import json
import argparse
import time
from datetime import datetime
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
import requests
from colorama import init, Fore, Style

init(autoreset=True)

class SocialEngineeringDetector:
    """
    Social Engineering Detection System
    """
    
    def __init__(self):
        self.risk_score = 0
        self.findings = []
        
        # Social engineering patterns
        self.urgency_patterns = [
            r'urgent|immediate|asap|right away',
            r'account.*(suspended|closed|limited)',
            r'legal.*action|lawsuit|court',
            r'warrant.*arrest|police',
            r'(24|48) hours',
            r'deadline|expires?',
            r'final.*warning|last chance'
        ]
        
        self.financial_patterns = [
            r'credit card|debit card',
            r'bank account|routing number',
            r'social security|ssn',
            r'wire transfer|western union',
            r'gift card|itunes card',
            r'paypal|venmo|cash app',
            r'verify.*(pin|password|code)',
            r'atm|bitcoin|cryptocurrency'
        ]
        
        self.authority_patterns = [
            r'irs|tax|treasury',
            r'social security administration',
            r'fbi|cia|dhs|homeland security',
            r'court|judge|attorney',
            r'police|sheriff|law enforcement',
            r'microsoft|apple|google support',
            r'tech support|customer service',
            r'fraud department|security team'
        ]
        
        self.scare_tactics = [
            r'virus.*detected|infected',
            r'identity theft|stolen identity',
            r'hacked|compromised',
            r'criminal.*activity',
            r'investigation|audit',
            r'deportation|immigration',
            r'prison|jail|arrest'
        ]
        
        self.generic_greetings = [
            r'dear (customer|user|account holder)',
            r'valued (customer|member)',
            r'hello (sir|madam)',
            r'to whom it may concern',
            r'dear (friend|neighbor)'
        ]
        
        self.suspicious_requests = [
            r'confirm.*(identity|information)',
            r'verify.*(account|details)',
            r'update.*(records|profile)',
            r'click.*link',
            r'download.*(software|app)',
            r'install.*(program|update)',
            r'call.*number',
            r'text.*code'
        ]
        
    def analyze_phone_call(self, caller_id, conversation_text, duration=None):
        """Analyze a phone call for social engineering"""
        results = {
            'type': 'phone_call',
            'timestamp': datetime.now().isoformat(),
            'caller_id': caller_id,
            'duration': duration,
            'risk_score': 0,
            'risk_level': 'LOW',
            'findings': [],
            'recommendations': []
        }
        
        # Analyze caller ID
        caller_analysis = self.analyze_caller_id(caller_id)
        results.update(caller_analysis)
        
        # Analyze conversation
        if conversation_text:
            text_analysis = self.analyze_text(conversation_text)
            results['findings'].extend(text_analysis['findings'])
            results['risk_score'] += text_analysis['risk_score']
        
        # Check for robocall indicators
        if self.is_robocall(conversation_text):
            results['findings'].append({
                'type': 'robocall',
                'severity': 'HIGH',
                'description': 'Conversation has robocall characteristics'
            })
            results['risk_score'] += 30
        
        # Calculate final risk level
        results['risk_level'] = self.get_risk_level(results['risk_score'])
        
        # Generate recommendations
        results['recommendations'] = self.generate_recommendations(results)
        
        return results
    
    def analyze_text_message(self, sender, message_text):
        """Analyze a text message for social engineering"""
        results = {
            'type': 'text_message',
            'timestamp': datetime.now().isoformat(),
            'sender': sender,
            'message_length': len(message_text),
            'risk_score': 0,
            'risk_level': 'LOW',
            'findings': [],
            'recommendations': []
        }
        
        # Analyze sender
        if self.is_suspicious_sender(sender):
            results['findings'].append({
                'type': 'suspicious_sender',
                'severity': 'HIGH',
                'description': f'Sender appears suspicious: {sender}'
            })
            results['risk_score'] += 20
        
        # Analyze message
        text_analysis = self.analyze_text(message_text)
        results['findings'].extend(text_analysis['findings'])
        results['risk_score'] += text_analysis['risk_score']
        
        # Check for shortened URLs
        urls = self.extract_urls(message_text)
        for url in urls:
            if self.is_shortened_url(url):
                results['findings'].append({
                    'type': 'shortened_url',
                    'severity': 'MEDIUM',
                    'description': f'Message contains shortened URL: {url}'
                })
                results['risk_score'] += 15
        
        # Calculate risk level
        results['risk_level'] = self.get_risk_level(results['risk_score'])
        
        # Generate recommendations
        results['recommendations'] = self.generate_recommendations(results)
        
        return results
    
    def analyze_email(self, sender, subject, body):
        """Analyze an email for social engineering"""
        results = {
            'type': 'email',
            'timestamp': datetime.now().isoformat(),
            'sender': sender,
            'subject': subject,
            'body_length': len(body),
            'risk_score': 0,
            'risk_level': 'LOW',
            'findings': [],
            'recommendations': []
        }
        
        # Analyze sender
        if self.is_suspicious_sender(sender):
            results['findings'].append({
                'type': 'suspicious_sender',
                'severity': 'HIGH',
                'description': f'Sender appears suspicious: {sender}'
            })
            results['risk_score'] += 20
        
        # Analyze subject
        subject_analysis = self.analyze_text(subject)
        results['findings'].extend(subject_analysis['findings'])
        results['risk_score'] += subject_analysis['risk_score']
        
        # Analyze body
        body_analysis = self.analyze_text(body)
        results['findings'].extend(body_analysis['findings'])
        results['risk_score'] += body_analysis['risk_score']
        
        # Calculate risk level
        results['risk_level'] = self.get_risk_level(results['risk_score'])
        
        # Generate recommendations
        results['recommendations'] = self.generate_recommendations(results)
        
        return results
    
    def analyze_in_person_interaction(self, description, visitor_info=None):
        """Analyze an in-person interaction for social engineering"""
        results = {
            'type': 'in_person',
            'timestamp': datetime.now().isoformat(),
            'visitor_info': visitor_info or {},
            'description': description[:200] + '...' if len(description) > 200 else description,
            'risk_score': 0,
            'risk_level': 'LOW',
            'findings': [],
            'recommendations': []
        }
        
        # Check for common pretexting scenarios
        scenarios = self.identify_scenarios(description)
        for scenario in scenarios:
            results['findings'].append({
                'type': 'scenario_match',
                'severity': scenario['severity'],
                'description': f'Matches {scenario["name"]} scenario: {scenario["description"]}'
            })
            results['risk_score'] += scenario['score']
        
        # Analyze visitor info if available
        if visitor_info:
            if not visitor_info.get('id_verified'):
                results['findings'].append({
                    'type': 'unverified_id',
                    'severity': 'HIGH',
                    'description': 'Visitor ID not verified'
                })
                results['risk_score'] += 20
            
            if visitor_info.get('no_appointment'):
                results['findings'].append({
                    'type': 'no_appointment',
                    'severity': 'MEDIUM',
                    'description': 'Visitor has no appointment'
                })
                results['risk_score'] += 10
        
        # Calculate risk level
        results['risk_level'] = self.get_risk_level(results['risk_score'])
        
        # Generate recommendations
        results['recommendations'] = self.generate_recommendations(results)
        
        return results
    
    def analyze_caller_id(self, caller_id):
        """Analyze caller ID information"""
        results = {
            'caller_id_analysis': {},
            'risk_score': 0
        }
        
        # Try to parse phone number
        try:
            if caller_id and caller_id != 'Unknown' and caller_id != 'Blocked':
                parsed = phonenumbers.parse(caller_id, 'US')
                
                results['caller_id_analysis'] = {
                    'valid': phonenumbers.is_valid_number(parsed),
                    'possible': phonenumbers.is_possible_number(parsed),
                    'country': geocoder.description_for_number(parsed, 'en'),
                    'carrier': carrier.name_for_number(parsed, 'en'),
                    'timezone': timezone.time_zones_for_number(parsed),
                    'type': 'mobile' if carrier.name_for_number(parsed, 'en') else 'landline'
                }
                
                # Check for VoIP (often used by scammers)
                if 'VOIP' in results['caller_id_analysis'].get('carrier', '').upper():
                    results['findings'] = {
                        'type': 'voip_caller',
                        'severity': 'MEDIUM',
                        'description': 'Caller uses VoIP service (common for scammers)'
                    }
                    results['risk_score'] += 15
                    
        except Exception:
            results['caller_id_analysis'] = {
                'valid': False,
                'note': 'Could not parse number'
            }
            
            # Suspicious caller ID formats
            if caller_id in ['Unknown', 'Blocked', 'Private', 'Restricted']:
                results['findings'] = {
                    'type': 'hidden_caller_id',
                    'severity': 'HIGH',
                    'description': f'Caller ID is hidden: {caller_id}'
                }
                results['risk_score'] += 25
            elif re.match(r'^\d{1,3}$', caller_id):  # Very short numbers
                results['findings'] = {
                    'type': 'suspicious_caller_id',
                    'severity': 'MEDIUM',
                    'description': f'Suspicious caller ID format: {caller_id}'
                }
                results['risk_score'] += 20
        
        return results
    
    def analyze_text(self, text):
        """Analyze text for social engineering patterns"""
        results = {
            'findings': [],
            'risk_score': 0
        }
        
        text_lower = text.lower()
        
        # Check for urgency patterns
        for pattern in self.urgency_patterns:
            if re.search(pattern, text_lower):
                results['findings'].append({
                    'type': 'urgency',
                    'severity': 'HIGH',
                    'description': f'Contains urgency language: {pattern}'
                })
                results['risk_score'] += 15
        
        # Check for financial requests
        for pattern in self.financial_patterns:
            if re.search(pattern, text_lower):
                results['findings'].append({
                    'type': 'financial_request',
                    'severity': 'CRITICAL',
                    'description': f'Requests financial information: {pattern}'
                })
                results['risk_score'] += 25
        
        # Check for authority claims
        for pattern in self.authority_patterns:
            if re.search(pattern, text_lower):
                results['findings'].append({
                    'type': 'authority_claim',
                    'severity': 'HIGH',
                    'description': f'Claims authority: {pattern}'
                })
                results['risk_score'] += 20
        
        # Check for scare tactics
        for pattern in self.scare_tactics:
            if re.search(pattern, text_lower):
                results['findings'].append({
                    'type': 'scare_tactic',
                    'severity': 'HIGH',
                    'description': f'Uses scare tactics: {pattern}'
                })
                results['risk_score'] += 20
        
        # Check for generic greetings
        for pattern in self.generic_greetings:
            if re.search(pattern, text_lower):
                results['findings'].append({
                    'type': 'generic_greeting',
                    'severity': 'MEDIUM',
                    'description': f'Uses generic greeting: {pattern}'
                })
                results['risk_score'] += 10
        
        # Check for suspicious requests
        for pattern in self.suspicious_requests:
            if re.search(pattern, text_lower):
                results['findings'].append({
                    'type': 'suspicious_request',
                    'severity': 'HIGH',
                    'description': f'Makes suspicious request: {pattern}'
                })
                results['risk_score'] += 15
        
        return results
    
    def is_suspicious_sender(self, sender):
        """Check if sender appears suspicious"""
        suspicious_patterns = [
            r'@.*\.(tk|ml|ga|cf|gq|xyz|top|win)$',
            r'noreply@',
            r'no-reply@',
            r'service@',
            r'help@',
            r'security@',
            r'admin@',
            r'support@'
        ]
        
        sender_lower = sender.lower()
        for pattern in suspicious_patterns:
            if re.search(pattern, sender_lower):
                return True
        
        return False
    
    def is_robocall(self, conversation):
        """Check if conversation has robocall characteristics"""
        indicators = 0
        
        # Check for scripted responses
        if conversation and len(conversation) < 50:  # Very short
            indicators += 1
        
        # Check for repeated phrases
        words = conversation.lower().split()
        if len(set(words)) < len(words) * 0.7:  # High repetition
            indicators += 1
        
        # Check for unnatural pauses (would need audio analysis)
        
        return indicators >= 2
    
    def extract_urls(self, text):
        """Extract URLs from text"""
        url_pattern = r'https?://[^\s<>"\'(){}|\\^`\[\]]+|bit\.ly/[^\s]+|tinyurl\.com/[^\s]+'
        return re.findall(url_pattern, text, re.IGNORECASE)
    
    def is_shortened_url(self, url):
        """Check if URL is shortened"""
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'short.link']
        return any(shortener in url for shortener in shorteners)
    
    def identify_scenarios(self, description):
        """Identify common pretexting scenarios"""
        scenarios = []
        desc_lower = description.lower()
        
        # Tech support scenario
        if any(word in desc_lower for word in ['virus', 'infected', 'tech support', 'microsoft', 'apple']):
            scenarios.append({
                'name': 'Tech Support Scam',
                'severity': 'HIGH',
                'score': 25,
                'description': 'Claims computer has viruses or problems'
            })
        
        # Government impersonation
        if any(word in desc_lower for word in ['irs', 'tax', 'fbi', 'police', 'warrant', 'court']):
            scenarios.append({
                'name': 'Government Impersonation',
                'severity': 'CRITICAL',
                'score': 30,
                'description': 'Claims to be from government agency'
            })
        
        # Charity scam
        if any(word in desc_lower for word in ['charity', 'donation', 'fundraiser', 'non-profit']):
            scenarios.append({
                'name': 'Charity Scam',
                'severity': 'MEDIUM',
                'score': 20,
                'description': 'Soliciting donations for fake charity'
            })
        
        # Romance scam
        if any(word in desc_lower for word in ['dating', 'relationship', 'love', 'romance', 'single']):
            scenarios.append({
                'name': 'Romance Scam',
                'severity': 'HIGH',
                'score': 25,
                'description': 'Building romantic relationship for financial gain'
            })
        
        # Grandparent scam
        if any(word in desc_lower for word in ['grandchild', 'grandson', 'granddaughter', 'family emergency']):
            scenarios.append({
                'name': 'Grandparent Scam',
                'severity': 'HIGH',
                'score': 25,
                'description': 'Posing as family member in distress'
            })
        
        # Lottery scam
        if any(word in desc_lower for word in ['lottery', 'prize', 'won', 'sweepstakes', 'winnings']):
            scenarios.append({
                'name': 'Lottery Scam',
                'severity': 'MEDIUM',
                'score': 20,
                'description': 'Claims you won a prize requiring payment'
            })
        
        return scenarios
    
    def get_risk_level(self, score):
        """Get risk level from score"""
        if score >= 70:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    @staticmethod
    def _dedupe_recommendations(recommendations):
        """Keep the first recommendation for each action (the same advice was printed twice)."""
        seen, unique = set(), []
        for rec in recommendations:
            if rec['action'] not in seen:
                seen.add(rec['action'])
                unique.append(rec)
        return unique

    def generate_recommendations(self, results):
        return self._dedupe_recommendations(self._build_recommendations(results))

    def _build_recommendations(self, results):
        """Generate recommendations based on findings"""
        recommendations = []
        
        if results['risk_level'] in ['CRITICAL', 'HIGH']:
            recommendations.append({
                'priority': 'IMMEDIATE',
                'action': 'Do not engage further',
                'details': 'End the conversation immediately'
            })
            
            recommendations.append({
                'priority': 'IMMEDIATE',
                'action': 'Verify through official channels',
                'details': 'Contact the organization directly using verified contact information'
            })
            
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Report incident',
                'details': 'Report this interaction to appropriate authorities (FTC, FBI, local police)'
            })
        
        elif results['risk_level'] == 'MEDIUM':
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Verify independently',
                'details': 'Do not provide information. Verify the request through separate channels.'
            })
            
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Document interaction',
                'details': 'Take notes on the interaction for future reference'
            })
        
        else:
            recommendations.append({
                'priority': 'LOW',
                'action': 'Stay vigilant',
                'details': 'No immediate threat detected, but remain cautious'
            })
        
        # Specific recommendations based on findings
        for finding in results.get('findings', []):
            if finding['type'] == 'financial_request':
                recommendations.append({
                    'priority': 'CRITICAL',
                    'action': 'Never share financial information',
                    'details': 'Legitimate organizations never ask for financial information over phone/email'
                })
            
            elif finding['type'] == 'urgency':
                recommendations.append({
                    'priority': 'HIGH',
                    'action': 'Ignore urgency claims',
                    'details': 'Scammers create urgency to bypass your judgment. Take time to verify.'
                })
        
        return recommendations
    
    def print_results(self, results):
        """Print analysis results"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 SOCIAL ENGINEERING ANALYSIS RESULTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Basic info
        print(f"\n{Fore.GREEN}Interaction Type: {results['type'].upper()}{Style.RESET_ALL}")
        print(f"Timestamp: {results['timestamp']}")
        
        # Risk level
        risk_color = {
            'LOW': Fore.GREEN,
            'MEDIUM': Fore.YELLOW,
            'HIGH': Fore.RED,
            'CRITICAL': Fore.RED + Style.BRIGHT
        }.get(results['risk_level'], Fore.WHITE)
        
        print(f"\n{risk_color}Risk Level: {results['risk_level']} (Score: {results['risk_score']}){Style.RESET_ALL}")
        
        # Caller/sender info
        if results['type'] == 'phone_call':
            print(f"\n{Fore.CYAN}Caller Information:{Style.RESET_ALL}")
            print(f"  Caller ID: {results.get('caller_id', 'Unknown')}")
            if 'caller_id_analysis' in results:
                analysis = results['caller_id_analysis']
                if analysis.get('valid'):
                    print(f"  Country: {analysis.get('country', 'Unknown')}")
                    print(f"  Carrier: {analysis.get('carrier', 'Unknown')}")
                    print(f"  Type: {analysis.get('type', 'Unknown')}")
        
        elif results['type'] == 'text_message':
            print(f"\n{Fore.CYAN}Message Information:{Style.RESET_ALL}")
            print(f"  Sender: {results.get('sender', 'Unknown')}")
            print(f"  Length: {results.get('message_length', 0)} characters")
        
        elif results['type'] == 'email':
            print(f"\n{Fore.CYAN}Email Information:{Style.RESET_ALL}")
            print(f"  Sender: {results.get('sender', 'Unknown')}")
            print(f"  Subject: {results.get('subject', 'None')}")
        
        # Findings
        if results.get('findings'):
            print(f"\n{Fore.RED}Findings ({len(results['findings'])}):{Style.RESET_ALL}")
            for finding in results['findings']:
                severity_color = {
                    'LOW': Fore.CYAN,
                    'MEDIUM': Fore.YELLOW,
                    'HIGH': Fore.RED,
                    'CRITICAL': Fore.RED + Style.BRIGHT
                }.get(finding.get('severity', 'MEDIUM'), Fore.WHITE)
                
                print(f"  {severity_color}• [{finding['severity']}] {finding['description']}{Style.RESET_ALL}")
        
        # Recommendations
        if results.get('recommendations'):
            print(f"\n{Fore.GREEN}Recommendations:{Style.RESET_ALL}")
            for rec in results['recommendations']:
                priority_color = {
                    'IMMEDIATE': Fore.RED,
                    'HIGH': Fore.YELLOW,
                    'MEDIUM': Fore.CYAN,
                    'LOW': Fore.GREEN
                }.get(rec['priority'], Fore.WHITE)
                
                print(f"  {priority_color}• [{rec['priority']}] {rec['action']}{Style.RESET_ALL}")
                print(f"    {rec['details']}")
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Social Engineering Detector')
    parser.add_argument('--type', choices=['call', 'sms', 'email', 'in-person'], 
                       required=True, help='Type of interaction to analyze')
    parser.add_argument('--caller', help='Caller ID for phone calls')
    parser.add_argument('--sender', help='Sender for SMS/email')
    parser.add_argument('--subject', help='Email subject')
    parser.add_argument('--message', help='Message/conversation text')
    parser.add_argument('--description', help='Description of in-person interaction')
    parser.add_argument('--duration', type=int, help='Call duration in seconds')
    parser.add_argument('--visitor', help='JSON file with visitor information')
    
    args = parser.parse_args()
    
    print(f"""
    {Fore.CYAN}╔═══════════════════════════════════════╗
    ║   Social Engineering Detector v1.0   ║
    ╚═══════════════════════════════════════╝{Style.RESET_ALL}
    """)
    
    detector = SocialEngineeringDetector()
    
    # Load visitor info if provided
    visitor_info = None
    if args.visitor:
        try:
            with open(args.visitor, 'r') as f:
                visitor_info = json.load(f)
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading visitor info: {e}{Style.RESET_ALL}")
    
    # Analyze based on type
    if args.type == 'call':
        if not args.caller or not args.message:
            print(f"{Fore.RED}[!] Phone call analysis requires --caller and --message{Style.RESET_ALL}")
            return
        
        results = detector.analyze_phone_call(args.caller, args.message, args.duration)
        detector.print_results(results)
    
    elif args.type == 'sms':
        if not args.sender or not args.message:
            print(f"{Fore.RED}[!] SMS analysis requires --sender and --message{Style.RESET_ALL}")
            return
        
        results = detector.analyze_text_message(args.sender, args.message)
        detector.print_results(results)
    
    elif args.type == 'email':
        if not args.sender or not args.message:
            print(f"{Fore.RED}[!] Email analysis requires --sender and --message{Style.RESET_ALL}")
            return
        
        results = detector.analyze_email(args.sender, args.subject or '', args.message)
        detector.print_results(results)
    
    elif args.type == 'in-person':
        if not args.description:
            print(f"{Fore.RED}[!] In-person analysis requires --description{Style.RESET_ALL}")
            return
        
        results = detector.analyze_in_person_interaction(args.description, visitor_info)
        detector.print_results(results)

if __name__ == "__main__":
    main()
