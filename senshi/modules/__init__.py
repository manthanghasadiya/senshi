from senshi.modules.ssti import SSTIModule
from senshi.modules.deserialization import DeserializationModule
from senshi.modules.sqli import SQLInjectionModule
from senshi.modules.xss import XSSModule
from senshi.modules.ssrf import SSRFModule
from senshi.modules.cmdi import CommandInjectionModule
from senshi.modules.idor import IDORModule
from senshi.modules.auth import AuthBypassModule
from senshi.modules.info_disclosure import InfoDisclosureModule
from senshi.modules.open_redirect import OpenRedirectModule

VULNERABILITY_MODULES = {
    # Critical
    "ssti": SSTIModule,
    "deserialization": DeserializationModule,
    "cmdi": CommandInjectionModule,
    "sqli": SQLInjectionModule,
    
    # High
    "xss": XSSModule,
    "ssrf": SSRFModule,
    "idor": IDORModule,
    "auth": AuthBypassModule,
    "open_redirect": OpenRedirectModule,
    
    # Medium
    "info_disclosure": InfoDisclosureModule,
}
