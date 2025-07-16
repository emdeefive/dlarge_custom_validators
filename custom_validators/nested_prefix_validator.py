# this module is a customer validator for Nautobot to prevent nested prefixes of type 'network'
# -*- coding: utf-8 -*-

from nautobot_data_validation_engine.custom_validators import DataComplianceRule, ComplianceError
from nautobot.ipam.models import Prefix
import ipaddress

class NoNestedPrefixesValidator(DataComplianceRule):
    model = "ipam.Prefix"
    enforce = True

    def audit(self):
        obj = self.context["object"]
        
        if not obj or not hasattr(obj, "network") or not hasattr(obj, "prefix_length"):
            return
            
        # Create an IPNetwork object for the current prefix
        try:
            prefix_cidr = f"{obj.network}/{obj.prefix_length}"
            current_network = ipaddress.ip_network(prefix_cidr)
        except ValueError:
            return
            
        # Get all prefixes except the current one
        other_prefixes = Prefix.objects.exclude(pk=obj.pk).filter(type="network")
        
        # Check for overlaps manually
        for other in other_prefixes:
            try:
                other_cidr = f"{other.network}/{other.prefix_length}"
                other_network = ipaddress.ip_network(other_cidr)
                
                # Check if they overlap
                if (current_network.subnet_of(other_network) or other_network.subnet_of(current_network)):
                    raise ComplianceError(
                        f"Nested prefixes of type 'network' are not allowed. "
                        f"This prefix {prefix_cidr} overlaps with existing network prefix {other_cidr}."
                    )
            except ValueError:
                continue