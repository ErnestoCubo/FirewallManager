try:
    from src.models.firewall import Firewall
    from src.models.firewall_policy import FirewallPolicy
except ImportError:
    from models.firewall import Firewall
    from models.firewall_policy import FirewallPolicy

def set_firewall_policies(firewall, data):
    policies_ids = data.get("policies_ids", [])
    if policies_ids:
        policies = FirewallPolicy.query.filter(FirewallPolicy.id.in_(policies_ids)).all()
        for policy in policies:
            if policy not in firewall.policies:
                firewall.policies.append(policy)

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