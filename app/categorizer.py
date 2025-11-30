from typing import List, Dict
from collections import defaultdict

class Categorizer:
    def categorize(self, iocs: List[Dict]) -> Dict:
        """Organize IOCs by type with unique counts"""
        categorized = defaultdict(list)
        
        for ioc in iocs:
            ioc_type = ioc['type']
            categorized[ioc_type].append(ioc)
        
        # Convert to dict with counts
        result = {}
        for ioc_type, ioc_list in categorized.items():
            result[ioc_type] = {
                'count': len(ioc_list),
                'items': ioc_list
            }
        
        return result
