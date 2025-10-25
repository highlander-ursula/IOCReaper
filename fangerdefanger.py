import re

class FangerDefanger:
    def fang(self, text: str) -> str:
        """Convert defanged IOCs to normal format"""
        # hxxp -> http
        text = re.sub(r'hxxp', 'http', text, flags=re.IGNORECASE)
        # example[.]com -> example.com
        text = re.sub(r'\[\.\]', '.', text)
        # example[dot]com -> example.com
        text = re.sub(r'\[dot\]', '.', text, flags=re.IGNORECASE)
        return text
    
    def defang(self, text: str) -> str:
        """Convert IOCs to defanged format"""
        # http -> hxxp
        text = re.sub(r'http', 'hxxp', text, flags=re.IGNORECASE)
        # . -> [.]
        text = re.sub(r'\.', '[.]', text)
        return text