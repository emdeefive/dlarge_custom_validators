# this module is a customer validator for Nautobot to prevent nested prefixes of type 'network'
# -*- coding: utf-8 -*-

from nautobot_data_validation_engine.custom_validators import DataComplianceRule, ComplianceError
from nautobot.ipam.models import Prefix

class NoNestedPrefixesValidator(DataComplianceRule):
    model = "ipam.prefix"
    enforce = True

    def audit(self):
        # Skip validation on delete
        if obj._state.adding is False and obj.present_in_database is False:
            return

        # Find any prefixes that contain this one or are contained by this one
        nested_prefixes = Prefix.objects.filter(
            prefix__net_contains_or_equals=obj.prefix
        ).exclude(pk=obj.pk).filter(type="network")
        
        container_prefixes = Prefix.objects.filter(
            prefix__net_contained=obj.prefix
        ).filter(type="network")
        
        if nested_prefixes.exists() or container_prefixes.exists():
            self.fail(
                "Nested prefixes of type 'network' are not allowed. This prefix overlaps with existing network prefixes."
            )