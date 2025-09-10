try:
    from src.models.firewall_rule import FirewallRule
except ImportError:
    from models.firewall_rule import FirewallRule

def update_firewall_rule_fields(firewall_rule, data):
    fields = ['name', 'description', 'action', 'source_ip', 'destination_ip', 'protocol', 'port', 'is_active', 'last_modified_by']
    for field in fields:
        if field in data:
            setattr(firewall_rule, field, data.get(field, getattr(firewall_rule, field)))
    return firewall_rule