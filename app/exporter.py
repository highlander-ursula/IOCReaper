import json
import csv
from io import StringIO
from typing import Tuple

class Exporter:
    def export(self, session_manager, format: str, include_tags: bool = False) -> Tuple[bytes, str, str]:
        """Export IOCs in specified format"""
        iocs = session_manager.get_iocs()
        
        if format.lower() == 'json':
            return self._export_json(iocs, include_tags)
        elif format.lower() == 'csv':
            return self._export_csv(iocs, include_tags)
        elif format.lower() == 'txt':
            return self._export_txt(iocs, include_tags)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _export_json(self, iocs: dict, include_tags: bool) -> Tuple[bytes, str, str]:
        """Export as JSON"""
        export_data = []
        for ioc_type, data in iocs.items():
            for ioc in data['items']:
                item = {
                    'value': ioc['value'],
                    'type': ioc['type']
                }
                if include_tags:
                    item['tags'] = ioc['tags']
                export_data.append(item)
        
        content = json.dumps(export_data, indent=2).encode('utf-8')
        return content, 'iocs.json', 'application/json'
    
    def _export_csv(self, iocs: dict, include_tags: bool) -> Tuple[bytes, str, str]:
        """Export as CSV"""
        output = StringIO()
        fieldnames = ['value', 'type']
        if include_tags:
            fieldnames.append('tags')
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for ioc_type, data in iocs.items():
            for ioc in data['items']:
                row = {
                    'value': ioc['value'],
                    'type': ioc['type']
                }
                if include_tags:
                    row['tags'] = ','.join(ioc['tags'])
                writer.writerow(row)
        
        content = output.getvalue().encode('utf-8')
        return content, 'iocs.csv', 'text/csv'
    
    def _export_txt(self, iocs: dict, include_tags: bool) -> Tuple[bytes, str, str]:
        """Export as plain text"""
        lines = []
        for ioc_type, data in iocs.items():
            for ioc in data['items']:
                line = ioc['value']
                if include_tags and ioc['tags']:
                    line += f" [Tags: {', '.join(ioc['tags'])}]"
                lines.append(line)
        
        content = '\n'.join(lines).encode('utf-8')
        return content, 'iocs.txt', 'text/plain'