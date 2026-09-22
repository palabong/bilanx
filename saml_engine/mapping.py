from typing import Dict, Any, Optional

class POSUserContext:
    def __init__(self, user_id: str, role: str, permissions: list[str], level_of_assurance: str, store_id: str = "STORE-001"):
        self.user_id = user_id
        self.role = role
        self.permissions = permissions
        self.level_of_assurance = level_of_assurance
        self.store_id = store_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "role": self.role,
            "permissions": self.permissions,
            "level_of_assurance": self.level_of_assurance,
            "store_id": self.store_id
        }

class SAMLToPOSMapper:
    @staticmethod
    def map_claims_to_pos(claims: Dict[str, Any]) -> POSUserContext:
        """
        Maps standard SAML claims extracted from the eIDAS schemas into actionable POS roles & permissions.
        """
        loa_uri = claims.get("level_of_assurance") or ""
        issuer = claims.get("issuer") or ""
        
        # Default credentials for low assurance
        role = "CASHIER"
        permissions = ["SHIFT_START", "SCAN_ITEM", "APPLY_COUPON", "CASH_TRANSACTION"]
        loa_level = "LOW"

        # Check eIDAS Level of Assurance
        if "LoA/substantial" in loa_uri or "LoA/high" in loa_uri:
            loa_level = "HIGH"
            role = "STORE_MANAGER"
            permissions = [
                "SHIFT_START", 
                "SCAN_ITEM", 
                "APPLY_COUPON", 
                "CASH_TRANSACTION",
                "MANAGER_OVERRIDE", 
                "VOID_TRANSACTION", 
                "REFUND_OVERRIDE", 
                "DRAWER_ACCESS"
            ]
        elif "LoA/low" in loa_uri:
            loa_level = "LOW"
            role = "CASHIER"
            permissions = ["SHIFT_START", "SCAN_ITEM", "APPLY_COUPON", "CASH_TRANSACTION"]

        # Parse subject/user_id from Issuer and ID structure
        subj_raw = claims.get("id", "UNKNOWN_SUBJECT")
        user_id = f"ID-{subj_raw[-8:]}" if len(subj_raw) > 8 else subj_raw

        return POSUserContext(
            user_id=user_id,
            role=role,
            permissions=permissions,
            level_of_assurance=loa_level,
            store_id="STORE-BELGIUM-BRU-01" if "Belgium" in issuer or "S-PEPS.gov.xx" in issuer else "STORE-METADATA-01"
        )
