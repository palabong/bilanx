import unittest
from engine import SAMLValidationEngine
from mapping import SAMLToPOSMapper
from fixtures import AUTHN_REQUEST_XML, RESPONSE_XML

class TestSAMLEngineAndMapper(unittest.TestCase):
    def setUp(self):
        self.allowed_issuers = [
            "http://S-PEPS.gov.xx",
            "http://cef-eid-build-1:8080/EidasNode/ServiceMetadata"
        ]
        self.allowed_destinations = [
            "http://peps.local:9090/PEPS/ServiceProvider",
            "http://cef-eid-build-1:8080/EidasNode/ColleagueResponse"
        ]
        self.engine = SAMLValidationEngine(
            allowed_issuers=self.allowed_issuers,
            allowed_destinations=self.allowed_destinations
        )

    def test_authn_request_happy_path(self):
        """Validates that the provided sample AuthnRequest parses successfully."""
        res = self.engine.validate_authn_request(AUTHN_REQUEST_XML)
        self.assertTrue(res.is_valid, f"Failed parsing valid AuthnRequest: {res.error_message}")
        self.assertEqual(res.claims["issuer"], "http://S-PEPS.gov.xx")
        self.assertEqual(res.claims["level_of_assurance"], "http://eidas.europa.eu/LoA/low")

        # Check POS mapping
        pos_context = SAMLToPOSMapper.map_claims_to_pos(res.claims)
        self.assertEqual(pos_context.role, "CASHIER")
        self.assertIn("SHIFT_START", pos_context.permissions)

    def test_response_happy_path(self):
        """Validates that the provided sample Response parses successfully."""
        res = self.engine.validate_response(RESPONSE_XML)
        self.assertTrue(res.is_valid, f"Failed parsing valid Response: {res.error_message}")
        self.assertEqual(res.claims["issuer"], "http://cef-eid-build-1:8080/EidasNode/ServiceMetadata")
        self.assertEqual(res.claims["status_code"], "urn:oasis:names:tc:SAML:2.0:status:Success")

        # Check POS mapping (LoA substantial -> STORE_MANAGER)
        claims_with_substantial_loa = dict(res.claims, level_of_assurance="http://eidas.europa.eu/LoA/substantial")
        pos_context = SAMLToPOSMapper.map_claims_to_pos(claims_with_substantial_loa)
        self.assertEqual(pos_context.role, "STORE_MANAGER")
        self.assertIn("MANAGER_OVERRIDE", pos_context.permissions)

    def test_replay_protection(self):
        """Ensures that identical Assertion/Request IDs cannot be reprocessed."""
        res1 = self.engine.validate_authn_request(AUTHN_REQUEST_XML)
        self.assertTrue(res1.is_valid)

        res2 = self.engine.validate_authn_request(AUTHN_REQUEST_XML)
        self.assertFalse(res2.is_valid)
        self.assertIn("Replay Attack Detected", res2.error_message)

    def test_xml_bomb_defense(self):
        """Verifies that entity declarations / DTDs trigger immediate safety rejection."""
        malicious_xml = """<?xml version="1.0"?>
        <!DOCTYPE lolz [
         <!ENTITY lol "lol">
         <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
        ]>
        <saml2p:AuthnRequest ID="_fakeID" Destination="http://peps.local:9090/PEPS/ServiceProvider" IssueInstant="2011-11-30T16:09:57.824Z">
            <saml2:Issuer>http://S-PEPS.gov.xx</saml2:Issuer>
        </saml2p:AuthnRequest>"""
        
        res = self.engine.validate_authn_request(malicious_xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Security Violation", res.error_message)

    def test_untrusted_issuer(self):
        """Verifies that an unknown issuer is blocked immediately."""
        untrusted_xml = AUTHN_REQUEST_XML.replace("http://S-PEPS.gov.xx", "http://untrusted-node.org")
        res = self.engine.validate_authn_request(untrusted_xml)
        self.assertFalse(res.is_valid)
        self.assertIn("Untrusted Issuer", res.error_message)

if __name__ == "__main__":
    unittest.main()
