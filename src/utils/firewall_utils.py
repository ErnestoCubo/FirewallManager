from src.models.firewall import Firewall

def update_firewall_unique_field(firewall, data, field_name):
    if field_name in data and data[field_name] != getattr(firewall, field_name):
        existing_firewall = Firewall.query.filter_by(**{field_name: data[field_name]}).first()
        if existing_firewall:
            return False
            
        setattr(firewall, field_name, data.get(field_name, getattr(firewall, field_name)))
    
    return True

def update_firewall_fields(firewall, data):
    fields = ["description", "ip_address", "vendor", "model", "os_version", "country", "city"]
    for field in fields:
        if field in data:
            setattr(firewall, field, data.get(field, getattr(firewall, field)))