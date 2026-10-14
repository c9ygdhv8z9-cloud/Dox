#!/usr/bin/env python3
"""
OSINT Correlation Engine - Documentation Technique
Structure de corrélation de données entre sources publiques.
À des fins éducatives et de documentation technique uniquement.
"""

import requests
import json
import re
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class IdentityProfile:
    """Profil d'identité corrélé à travers les sources."""
    primary_identifier: str
    aliases: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)
    associations: Dict[str, List[str]] = field(default_factory=dict)
    breach_data: Dict[str, any] = field(default_factory=dict)
    metadata: Dict[str, any] = field(default_factory=dict)
    confidence_score: float = 0.0
    sources: List[str] = field(default_factory=list)


class OSINTCollector:
    """Collecteur de données OSINT multi-source."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        self.results = IdentityProfile(primary_identifier="")
    
    def search_search_engine(self, query: str, engine: str = "google") -> List[Dict]:
        """
        Recherche multi-moteur avec opérateurs avancés.
        Retourne les résultats indexés pertinents.
        """
        search_urls = {
            "google": f"https://www.google.com/search?q={query}",
            "duckduckgo": f"https://html.duckduckgo.com/html/?q={query}",
            "bing": f"https://www.bing.com/search?q={query}"
        }
        
        url = search_urls.get(engine, search_urls["google"])
        results = []
        
        try:
            response = self.session.get(url, timeout=10)
            # Extraction des résultats (simplifiée)
            # En production, utiliser des parsers HTML dédiés
            if response.status_code == 200:
                # Parser les liens et snippets
                link_pattern = re.findall(r'href="(http[^"]+)"', response.text)
                title_pattern = re.findall(r'<title>([^<]+)</title>', response.text)
                
                for link in link_pattern[:10]:
                    results.append({
                        "url": link,
                        "title": title_pattern[0] if title_pattern else "",
                        "engine": engine,
                        "timestamp": datetime.now().isoformat()
                    })
        except Exception as e:
            print(f"[ERROR] Recherche {engine} échouée: {e}")
        
        return results
    
    def email_reputation_check(self, email: str) -> Dict:
        """
        Vérifie la réputation d'un email et détecte les fuites associées.
        Utilise les APIs publiques de vérification.
        """
        result = {"emailresult = {"email": email, "breaches": [], "reputation": "unknown", "risk_level": "unknown"}
        
        # Vérification via Have I Been Pwned (API publique)
        try:
            hibp_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            response = self.session.get(hibp_url, timeout=10)
            if response.status_code == 200:
                breaches = response.json()
                for breach in breaches:
                    result["breaches"].append({
                        "name": breach.get("Name", ""),
                        "date": breach.get("BreachDate", ""),
                        "data_classes": breach.get("DataClasses", []),
                        "description": breach.get("Description", "")
                    })
                result["reputation"] = "compromised"
                result["risk_level"] = "high"
            elif response.status_code == 404:
                result["reputation"] = "not_found"
                result["risk_level"] = "low"
        except Exception as e:
            print(f"[ERROR] HIBP check failed for {email}: {e}")
        
        return result
    
    def phone_reverse_lookup(self, phone: str) -> Dict:
        """
        Recherche inverse de numéro de téléphone.
        """
        result = {"phone": phone, "carrier": None, "location": None, "type": None}
        
        try:
            # Nettoyage du numéro
            clean_phone = re.sub(r'[^\d+]', '', phone)
            # Appel à un service de lookup publique
            lookup_url = f"https://phonenumbers.org/number/{clean_phone}"
            response = self.session.get(lookup_url, timeout=10)
            if response.status_code == 200:
                # Extraction des informations
                carrier_match = re.search(r'Carrier:\s*([^<]+)', response.text)
                location_match = re.search(r'Location:\s*([^<]+)', response.text)
                
                if carrier_match:
                    result["carrier"] = carrier_match.group(1).strip()
                if location_match:
                    result["location"] = location_match.group(1).strip()
        except Exception as e:
            print(f"[ERROR] Phone lookup failed: {e}")
        
        return result
    
    def social_media_search(self, identifier: str) -> Dict[str, List[str]]:
        """
        Recherche d'un identifiant sur les réseaux sociaux.
        Retourne une carte des profils trouvés.
        """
        platforms = {
            "github": f"https://github.com/{identifier}",
            "twitter": f"https://twitter.com/{identifier}",
            "instagram": f"https://instagram.com/{identifier}",
            "linkedin": f"https://linkedin.com/in/{identifier}",
            "reddit": f"https://reddit.com/user/{identifier}",
            "tiktok": f"https://tiktok.com/@{identifier}",
            "youtube": f"https://youtube.com/{identifier}",
            "facebook": f"https://facebook.com/{identifier}"
        }
        
        found_profiles = {}
        
        for platform, url in platforms.items():
            try:
                response = self.session.head(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    found_profiles[platform] = url
            except Exception as e:
                pass
        
        return found_profiles
    
    def metadata_extraction(self, file_path: str) -> Dict:
        """
        Extraction des métadonnées d'un fichier.
        """
        import os
        import hashlib
        
        result = {"file": file_path, "metadata": {}, "checksums": {}}
        
        try:
            # Hash du fichier
            with open(file_path, 'rb') as f:
                file_data = f.read()
                result["checksums"]["md5"] = hashlib.md5(file_data).hexdigest()
                result["checksums"]["sha256"] = hashlib.sha256(file_data).hexdigest()
                result["checksums"]["sha1"] = hashlib.sha1(file_data).hexdigest()
            
            # Métadonnées du système de fichiers
            stat = os.stat(file_path)
            result["metadata"]["size"] = stat.st_size
            result["metadata"]["created"] = datetime.fromtimestamp(stat.st_ctime).isoformat()
            result["metadata"]["modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            result["metadata"]["accessed"] = datetime.fromtimestamp(stat.st_atime).isoformat()
        except Exception as e:
            print(f"[ERROR] Metadata extraction failed: {e}")
        
        return result
    
    def domain_reconnaissance(self, domain: str) -> Dict:
        """
        Reconnaissance d'un domaine : WHOIS, DNS, sous-domaines.
        """
        result = {"domain": domain, "whois": {}, "dns": {}, "subdomains": []}
        
        try:
            # WHOIS
            whois_url = f"https://whois.domaintools.com/{domain}"
            response = self.session.get(whois_url, timeout=10)
            if response.status_code == 200:
                # Extraction des infos WHOIS
                registrar_match = re.search(r'Registrar:\s*([^<]+)', response.text)
                date_match = re.search(r'Created Date:\s*([^<]+)', response.text)
                admin_match = re.search(r'Admin Name:\s*([^<]+)', response.text)
                
                if registrar_match:
                    result["whois"]["registrar"] = registrar_match.group(1).strip()
                if date_match:
                    result["whois"]["created"] = date_match.group(1).strip()
                if admin_match:
                    result["whois"]["admin"] = admin_match.group(1).strip()
        except Exception as e:
            print(f"[ERROR] WHOIS lookup failed: {e}")
        
        return result
    
    def generate_report(self, profile: IdentityProfile) -> str:
        """
        Génère un rapport structuré de toutes les données collectées.
        """
        report = []
        report.append("=" * 60)
        report.append("RAPPORT DE CORRÉLATION OSINT")
        report.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Cible: {profile.primary_identifier}")
        report.append(f"Score de confiance: {profile.confidence_score:.2f}")
        report.append("=" * 60)
        
        if profile.aliases:
            report.append("\n--- ALIASES ---")
            for alias in profile.aliases:
                report.append(f"  • {alias}")
        
        if profile.emails:
            report.append("\n--- EMAILS ---")
            for email in profile.emails:
                breach_info = profile.breach_data.get(email, {})
                report.append(f"  • {email} (risque: {breach_info.get('risk_level', 'unknown')})")
        
        if profile.phone_numbers:
            report.append("\n--- NUMÉROS DE TÉLÉPHONE ---")
            for phone in profile.phone_numbers:
                report.append(f"  • {phone}")
