# SAML XML Sample Files for Unit Testing

AUTHN_REQUEST_XML = """<saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" AssertionConsumerServiceURL="http://sp.local:9090/SP/ReturnPage" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" Destination="http://peps.local:9090/PEPS/ServiceProvider" ForceAuthn="true" ID="_d048cb317813845b32a7a2b75f3bad59" IsPassive="false" IssueInstant="2011-11-30T16:09:57.824Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ProviderName="DEMO-SP" Version="2.0">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://S-PEPS.gov.xx</saml2:Issuer>
    <saml2p:RequestedAuthnContext Comparison="minimum">
        <saml2:AuthnContextClassRef>http://eidas.europa.eu/LoA/low</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>
</saml2p:AuthnRequest>"""

RESPONSE_XML = """<saml2p:Response xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Consent="urn:oasis:names:tc:SAML:2.0:consent:obtained" Destination="http://cef-eid-build-1:8080/EidasNode/ColleagueResponse" ID="_7POlm0XG6RUlrv67ArCVMe4cjc4IjIO5S2fe74-0yYbPRqbjJYl-v2hE4l6sqA2" InResponseTo="_BWujh-SYHdY7qT35CXZ8y.yk5tSK793zQoiavTqXe.i_AuVw0f9RTOEQOihenSv" IssueInstant="2019-05-24T10:00:32.405Z" Version="2.0">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://cef-eid-build-1:8080/EidasNode/ServiceMetadata</saml2:Issuer>
    <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        <saml2p:StatusMessage>urn:oasis:names:tc:SAML:2.0:status:Success</saml2p:StatusMessage>
    </saml2p:Status>
</saml2p:Response>"""
