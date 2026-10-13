import { Bug, Globe, KeyRound, Network, ShieldCheck, Siren, Users } from "lucide-react";

const icons = {
  "network-security": Network,
  "web-application-security": Globe,
  "malware-analysis": Bug,
  "social-engineering": Users,
  cryptography: KeyRound,
  "incident-response": Siren,
};

export default function CategoryIcon({ slug, className = "size-5" }) {
  const Icon = icons[slug] ?? ShieldCheck;
  return <Icon className={className} aria-hidden="true" />;
}
