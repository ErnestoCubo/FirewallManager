try:
    from src.models.firewall_policy import FirewallPolicy
except ImportError:
    from models.firewall_policy import FirewallPolicy

def update_firewall_policy_unique_field(firewall_policy, data, field_name):
    if field_name in data and data[field_name] != getattr(firewall_policy, field_name):
        existing_firewall = FirewallPolicy.query.filter_by(**{field_name: data[field_name]}).first()
        if existing_firewall:
            return False

        setattr(firewall_policy, field_name, data.get(field_name, getattr(firewall_policy, field_name)))
    
    return True

def update_firewall_policy_fields(firewall_policy, data):
    fields = ['description', 'policy_type', 'is_active', 'priority', 'last_modified_by']
    for field in fields:
        if field in data:
            setattr(firewall_policy, field, data.get(field, getattr(firewall_policy, field)))
    return firewall_policy