from typing import List, Dict

class Searcher:
    def search(self, query: str, session_manager, case_sensitive: bool = False) -> List[Dict]:
        """Search for IOCs and tags"""
        results = []
        iocs = session_manager.get_iocs()
        
        if not case_sensitive:
            query = query.lower()
        
        for ioc_type, data in iocs.items():
            for ioc in data['items']:
                # Search in IOC value
                search_value = ioc['value'] if case_sensitive else ioc['value'].lower()
                if query in search_value:
                    results.append(ioc)
                    continue
                
                # Search in tags
                for tag in ioc['tags']:
                    search_tag = tag if case_sensitive else tag.lower()
                    if query in search_tag:
                        results.append(ioc)
                        break
        
        return results