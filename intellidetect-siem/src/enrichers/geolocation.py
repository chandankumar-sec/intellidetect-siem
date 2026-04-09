"""Geolocation Enrichment Module."""
from typing import Dict, Any, Optional

class GeoEnricher:
    """Enrich alerts with geolocation data."""
    
    MOCK_GEO_DATA = {
        '185.220.101.45': {'country': 'Germany', 'city': 'Frankfurt', 'org': 'Tor Network'},
        '45.33.32.156': {'country': 'United States', 'city': 'Fremont', 'org': 'Linode'},
        '198.51.100.99': {'country': 'Russia', 'city': 'Moscow', 'org': 'Unknown ISP'},
        '203.0.113.50': {'country': 'China', 'city': 'Beijing', 'org': 'China Telecom'},
    }
    
    def __init__(self, api_key: str = None, mock_mode: bool = True):
        self.api_key = api_key
        self.mock_mode = mock_mode
    
    def enrich_incident(self, incident) -> Any:
        """Enrich an incident with geolocation data."""
        countries = set()
        cities = set()
        
        for src_ip in incident.source_ips:
            geo_data = self._lookup_ip(src_ip)
            if geo_data.get('country'):
                countries.add(geo_data['country'])
            if geo_data.get('city'):
                cities.add(geo_data['city'])
        
        incident.geo_info = {
            'countries': list(countries),
            'cities': list(cities),
            'is_international': len(countries) > 1
        }
        
        return incident
    
    def _lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Look up geolocation for an IP address."""
        if self.mock_mode and ip in self.MOCK_GEO_DATA:
            return self.MOCK_GEO_DATA[ip]
        return {'country': 'Unknown', 'city': 'Unknown', 'org': 'Unknown'}
