from typing import Dict

class TagManager:
    def add_tag(self, ioc_value: str, tag: str, session_manager) -> Dict:
        """Add a tag to an IOC"""
        # Validate tag
        if not tag or not tag.strip():
            raise ValueError("Tag cannot be empty")
        
        # Check for forbidden characters
        forbidden_chars = ['<', '>', '"', "'", '&']
        if any(char in tag for char in forbidden_chars):
            raise ValueError("Tag contains forbidden characters")
        
        # Find and update IOC
        iocs = session_manager.get_iocs()
        found = False
        
        for ioc_type, data in iocs.items():
            for ioc in data['items']:
                if ioc['value'] == ioc_value:
                    if tag not in ioc['tags']:
                        ioc['tags'].append(tag)
                    found = True
                    break
        
        if not found:
            raise ValueError("IOC not found")
        
        return {"message": "Tag added successfully"}
    
    def remove_tag(self, ioc_value: str, tag: str, session_manager) -> Dict:
        """Remove a tag from an IOC"""
        iocs = session_manager.get_iocs()
        found = False
        
        for ioc_type, data in iocs.items():
            for ioc in data['items']:
                if ioc['value'] == ioc_value:
                    if tag in ioc['tags']:
                        ioc['tags'].remove(tag)
                    found = True
                    break
        
        if not found:
            raise ValueError("IOC not found")
        
        return {"message": "Tag removed successfully"}