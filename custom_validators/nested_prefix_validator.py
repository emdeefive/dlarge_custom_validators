# this module is a customer validator for Nautobot to prevent nested prefixes of type 'network'
# -*- coding: utf-8 -*-

from nautobot_data_validation_engine.custom_validators import DataComplianceRule, ComplianceError
from nautobot.ipam.models import Prefix

class NoNestedPrefixesValidator(DataComplianceRule):
    model = "ipam.Prefix"
    
    def validate(self):
        obj = self.context["object"]
        
        # Skip validation on delete
        if hasattr(obj, "_state") and obj._state.adding is False and obj.present_in_database is False:
            return
            
        # In v2.4.4, need to use network and prefix_length instead of prefix
        nested_prefixes = Prefix.objects.filter(
            network=obj.network,
            prefix_length__gt=obj.prefix_length
        ).exclude(pk=obj.pk).filter(type="network")
        
        container_prefixes = Prefix.objects.filter(
            network__startswith=obj.network,
            prefix_length__lt=obj.prefix_length
        ).filter(type="network")
        
        if nested_prefixes.exists() or container_prefixes.exists():
            self.fail(
                "Nested prefixes of type 'network' are not allowed. This prefix overlaps with existing network prefixes."
            )