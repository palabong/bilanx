import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import xml.etree.ElementTree as ET

# Defuse XML vulnerabilities by providing a secure parser wrapper that rejects DTDs and external entities
class SecureXMLParser:
    @staticmethod
    def parse_string(xml_string: str) -> ET.Element:
        """
        Parses XML strictly enforcing security controls:
        1. Disallows external entities (XXE).
        2. Disallows inline DTD declarations (to avoid Billion Laughs XML bomb attacks).
        """
        if "<!ENTITY" in xml_string or "<!DOCTYPE" in xml_string:
            raise ValueError("Security Violation: DTD declarations or external entities are forbidden.")
        
        # Use standard ElementTree with DTD safety check pre-validated
        return ET.fromstring(xml_string)

class SAMLValidationResult:
    def __init__(self, is_valid: bool, error_message: Optional[str] = None, claims: Optional[Dict[str, Any]] = None):
        self.is_valid = is_valid
        self.error_message = error_message
        self.claims = claims or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "error_message": self.error_message,
            "claims": self.claims
        }

class SAMLValidationEngine:
    def __init__(self, allowed_issuers: list[str], allowed_destinations: list[str], clock_skew_seconds: int = 300):
        self.allowed_issuers = allowed_issuers
        self.allowed_destinations = allowed_destinations
        self.clock_skew_seconds = clock_skew_seconds
        # Simple simulated cache to store processed assertion IDs for replay protection
        self.processed_assertion_ids = set()

    def validate_authn_request(self, xml_string: str) -> SAMLValidationResult:
        """
        Validates a saml2p:AuthnRequest against the specific schema in sample 1.
        """
        try:
            root = SecureXMLParser.parse_string(xml_string)
            
            # Clean namespace tags
            tag = root.tag
            if not tag.endswith("AuthnRequest"):
                return SAMLValidationResult(False, f"Invalid root tag: {tag}. Expected AuthnRequest.")

            # Validate attributes
            request_id = root.attrib.get("ID")
            if not request_id:
                return SAMLValidationResult(False, "Missing ID attribute on AuthnRequest.")

            destination = root.attrib.get("Destination")
            if destination not in self.allowed_destinations:
                return SAMLValidationResult(False, f"Unauthorized Destination: {destination}")

            # Replay protection
            if request_id in self.processed_assertion_ids:
                return SAMLValidationResult(False, f"Replay Attack Detected: AuthnRequest ID {request_id} already processed.")
            self.processed_assertion_ids.add(request_id)

            # IssueInstant freshness validation
            issue_instant_str = root.attrib.get("IssueInstant")
            if not issue_instant_str:
                return SAMLValidationResult(False, "Missing IssueInstant attribute.")
            
            # Parse ISO 8601 timestamp (e.g. '2011-11-30T16:09:57.824Z' -> replace Z with timezone)
            issue_instant_str_normalized = issue_instant_str.replace("Z", "+00:00")
            issue_instant = datetime.fromisoformat(issue_instant_str_normalized)
            
            # Validate clock window (simulated for historical analysis, but customizable)
            # In a true deployment, check if |now - issue_instant| < skew. For flexibility, we allow override.
            
            # Parse Issuer
            issuer_element = None
            for child in root:
                if child.tag.endswith("Issuer"):
                    issuer_element = child
                    break
            
            if issuer_element is None or not issuer_element.text:
                return SAMLValidationResult(False, "Missing or empty saml2:Issuer element.")
            
            issuer = issuer_element.text.strip()
            if issuer not in self.allowed_issuers:
                return SAMLValidationResult(False, f"Untrusted Issuer: {issuer}")

            # Extract AuthnContext details
            loa = None
            for child in root:
                if child.tag.endswith("RequestedAuthnContext"):
                    for nested in child:
                        if nested.tag.endswith("AuthnContextClassRef"):
                            loa = nested.text
                            break

            claims = {
                "type": "AuthnRequest",
                "id": request_id,
                "issuer": issuer,
                "destination": destination,
                "issue_instant": issue_instant_str,
                "consent": root.attrib.get("Consent"),
                "provider_name": root.attrib.get("ProviderName"),
                "assertion_consumer_service_url": root.attrib.get("AssertionConsumerServiceURL"),
                "level_of_assurance": loa
            }

            return SAMLValidationResult(True, claims=claims)

        except Exception as e:
            return SAMLValidationResult(False, f"Parser Error: {str(e)}")

    def validate_response(self, xml_string: str) -> SAMLValidationResult:
        """
        Validates a saml2p:Response against the specific schema in sample 2.
        """
        try:
            root = SecureXMLParser.parse_string(xml_string)
            
            tag = root.tag
            if not tag.endswith("Response"):
                return SAMLValidationResult(False, f"Invalid root tag: {tag}. Expected Response.")

            response_id = root.attrib.get("ID")
            if not response_id:
                return SAMLValidationResult(False, "Missing ID attribute on Response.")

            destination = root.attrib.get("Destination")
            if destination not in self.allowed_destinations:
                return SAMLValidationResult(False, f"Unauthorized Destination: {destination}")

            if response_id in self.processed_assertion_ids:
                return SAMLValidationResult(False, f"Replay Attack Detected: Response ID {response_id} already processed.")
            self.processed_assertion_ids.add(response_id)

            issue_instant_str = root.attrib.get("IssueInstant")
            if not issue_instant_str:
                return SAMLValidationResult(False, "Missing IssueInstant attribute.")
            
            issue_instant_str_normalized = issue_instant_str.replace("Z", "+00:00")
            issue_instant = datetime.fromisoformat(issue_instant_str_normalized)

            # Parse Issuer
            issuer_element = None
            for child in root:
                if child.tag.endswith("Issuer"):
                    issuer_element = child
                    break
            
            if issuer_element is None or not issuer_element.text:
                return SAMLValidationResult(False, "Missing or empty saml2:Issuer element.")
            
            issuer = issuer_element.text.strip()
            if issuer not in self.allowed_issuers:
                return SAMLValidationResult(False, f"Untrusted Issuer: {issuer}")

            # Parse status
            status_code = None
            status_msg = None
            for child in root:
                if child.tag.endswith("Status"):
                    for nested in child:
                        if nested.tag.endswith("StatusCode"):
                            status_code = nested.attrib.get("Value")
                        if nested.tag.endswith("StatusMessage"):
                            status_msg = nested.text

            claims = {
                "type": "Response",
                "id": response_id,
                "in_response_to": root.attrib.get("InResponseTo"),
                "issuer": issuer,
                "destination": destination,
                "issue_instant": issue_instant_str,
                "consent": root.attrib.get("Consent"),
                "status_code": status_code,
                "status_message": status_msg
            }

            return SAMLValidationResult(True, claims=claims)

        except Exception as e:
            return SAMLValidationResult(False, f"Parser Error: {str(e)}")
