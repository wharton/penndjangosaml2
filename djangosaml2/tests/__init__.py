# Copyright (C) 2010 Lorenzo Gil Sanchez
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import base64
import re
import urlparse

from django.contrib.auth import SESSION_KEY
from django.contrib.auth.models import User
from django.test import TestCase

from saml2.s_utils import decode_base64_and_inflate, deflate_and_base64_encode

from djangosaml2 import views
from djangosaml2.models import OutstandingQuery
from djangosaml2.tests import conf
from djangosaml2.tests.auth_response import auth_response


class SAML2Tests(TestCase):

    urls = 'djangosaml2.urls'

    def assertSAMLRequestsEquals(self, xml1, xml2):
        def remove_variable_attributes(xml_string):
            xml_string = re.sub(r' ID=".*?" ', ' ', xml_string)
            xml_string = re.sub(r' IssueInstant=".*?" ', ' ', xml_string)
            xml_string = re.sub(
                r'<ns1:NameID xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion">.*</ns1:NameID>',
                '<ns1:NameID xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion"></ns1:NameID>',
                xml_string)
            return xml_string

        self.assertEquals(remove_variable_attributes(xml1),
                          remove_variable_attributes(xml2))

    def test_login_one_idp(self):
        # monkey patch SAML configuration
        views._load_conf = conf.create_conf(sp_host='sp.example.com',
                                            idp_hosts=['idp.example.com'])

        response = self.client.get('/login/')
        self.assertEquals(response.status_code, 302)
        location = response['Location']

        url = urlparse.urlparse(location)
        self.assertEquals(url.hostname, 'idp.example.com')
        self.assertEquals(url.path, '/simplesaml/saml2/idp/SSOService.php')

        params = urlparse.parse_qs(url.query)
        self.assert_('SAMLRequest' in params)
        self.assert_('RelayState' in params)

        saml_request = params['SAMLRequest'][0]
        expected_request = """<?xml version='1.0' encoding='UTF-8'?>
<ns0:AuthnRequest AssertionConsumerServiceURL="http://sp.example.com/saml2/acs/" Destination="https://idp.example.com/simplesaml/saml2/idp/SSOService.php" ID="XXXXXXXXXXXXXXXXXXXXXX" IssueInstant="2010-01-01T00:00:00Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ProviderName="Test SP" Version="2.0" xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"><ns1:Issuer xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion">http://sp.example.com/saml2/metadata/</ns1:Issuer><ns0:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" /></ns0:AuthnRequest>"""
        xml = decode_base64_and_inflate(saml_request)
        self.assertSAMLRequestsEquals(expected_request, xml)

        # if we set a next arg in the login view, it is preserverd
        # in the RelayState argument
        next = '/another-view/'
        response = self.client.get('/login/', {'next': next})
        self.assertEquals(response.status_code, 302)
        location = response['Location']

        url = urlparse.urlparse(location)
        self.assertEquals(url.hostname, 'idp.example.com')
        self.assertEquals(url.path, '/simplesaml/saml2/idp/SSOService.php')

        params = urlparse.parse_qs(url.query)
        self.assert_('SAMLRequest' in params)
        self.assert_('RelayState' in params)
        self.assertEquals(params['RelayState'][0], next)

    def test_login_several_idps(self):
        views._load_conf = conf.create_conf(sp_host='sp.example.com',
                                            idp_hosts=['idp1.example.com',
                                                       'idp2.example.com',
                                                       'idp3.example.com'])
        response = self.client.get('/login/')
        # a WAYF page should be displayed
        self.assertContains(response, 'Where are you from?', status_code=200)
        for i in range(1, 4):
            link = '/login/?idp=https://idp%d.example.com/simplesaml/saml2/idp/metadata.php&next=/'
            self.assertContains(response, link % i)

        # click on the second idp
        response = self.client.get('/login/', {
                'idp': 'https://idp2.example.com/simplesaml/saml2/idp/metadata.php',
                'next': '/',
                })
        self.assertEquals(response.status_code, 302)
        location = response['Location']

        url = urlparse.urlparse(location)
        self.assertEquals(url.hostname, 'idp2.example.com')
        self.assertEquals(url.path, '/simplesaml/saml2/idp/SSOService.php')

        params = urlparse.parse_qs(url.query)
        self.assert_('SAMLRequest' in params)
        self.assert_('RelayState' in params)

        saml_request = params['SAMLRequest'][0]
        expected_request = """<?xml version='1.0' encoding='UTF-8'?>
<ns0:AuthnRequest AssertionConsumerServiceURL="http://sp.example.com/saml2/acs/" Destination="https://idp2.example.com/simplesaml/saml2/idp/SSOService.php" ID="XXXXXXXXXXXXXXXXXXXXXX" IssueInstant="2010-01-01T00:00:00Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ProviderName="Test SP" Version="2.0" xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"><ns1:Issuer xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion">http://sp.example.com/saml2/metadata/</ns1:Issuer><ns0:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" /></ns0:AuthnRequest>"""
        xml = decode_base64_and_inflate(saml_request)
        self.assertSAMLRequestsEquals(expected_request, xml)

    def test_assertion_consumer_service(self):
        # there are no users in the database
        self.assertEquals(User.objects.count(), 0)

        views._load_conf = conf.create_conf(sp_host='sp.example.com',
                                            idp_hosts=['idp.example.com'])


        config = views._load_conf()
        # session_id should start with a letter since it is a NCName
        session_id = "a0123456789abcdef0123456789abcdef"
        came_from = '/another-view/'
        saml_response = auth_response({'uid': 'student'}, session_id, config)
        OutstandingQuery.objects.create(session_id=session_id,
                                        came_from=came_from)
        # this will create a user
        response = self.client.post('/acs/', {
                'SAMLResponse': base64.b64encode(str(saml_response)),
                'RelayState': came_from,
                })
        self.assertEquals(response.status_code, 302)
        location = response['Location']

        url = urlparse.urlparse(location)
        self.assertEquals(url.hostname, 'testserver')
        self.assertEquals(url.path, came_from)

        self.assertEquals(User.objects.count(), 1)
        user_id = self.client.session[SESSION_KEY]
        user = User.objects.get(id=user_id)
        self.assertEquals(user.username, 'student')

        # let's create another user and log in with that one
        new_user = User.objects.create(username='teacher', password='not-used')

        session_id = "a1111111111111111111111111111111"
        came_from = '/'
        saml_response = auth_response({'uid': 'teacher'}, session_id, config)
        OutstandingQuery.objects.create(session_id=session_id,
                                        came_from=came_from)
        response = self.client.post('/acs/', {
                'SAMLResponse': base64.b64encode(str(saml_response)),
                'RelayState': came_from,
                })
        self.assertEquals(response.status_code, 302)
        self.assertEquals(new_user.id, self.client.session[SESSION_KEY])

    def test_logout(self):
        views._load_conf = conf.create_conf(sp_host='sp.example.com',
                                            idp_hosts=['idp.example.com'])

        # do the login first
        config = views._load_conf()
        session_id = "a0123456789abcdef0123456789abcdef"
        came_from = '/another-view/'
        saml_response = auth_response({'uid': 'student'}, session_id, config)
        OutstandingQuery.objects.create(session_id=session_id,
                                        came_from=came_from)
        # this will create a user
        response = self.client.post('/acs/', {
                'SAMLResponse': base64.b64encode(str(saml_response)),
                'RelayState': came_from,
                })
        self.assertEquals(response.status_code, 302)

        # now the logout
        response = self.client.get('/logout/')
        self.assertEquals(response.status_code, 302)
        location = response['Location']

        url = urlparse.urlparse(location)
        self.assertEquals(url.hostname, 'idp.example.com')
        self.assertEquals(url.path,
                          '/simplesaml/saml2/idp/SingleLogoutService.php')

        params = urlparse.parse_qs(url.query)
        self.assert_('SAMLRequest' in params)

        saml_request = params['SAMLRequest'][0]
        expected_request = """<?xml version='1.0' encoding='UTF-8'?>
<ns0:LogoutRequest Destination="https://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php" ID="XXXXXXXXXXXXXXXXXXXXXX" IssueInstant="2010-01-01T00:00:00Z" Version="2.0" xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"><ns1:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion">http://sp.example.com/saml2/metadata/</ns1:Issuer><ns1:NameID xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion">58bcc81ea14700f66aeb707a0eff1360</ns1:NameID></ns0:LogoutRequest>"""
        xml = decode_base64_and_inflate(saml_request)
        self.assertSAMLRequestsEquals(expected_request, xml)

    def test_logout_service(self):
        views._load_conf = conf.create_conf(sp_host='sp.example.com',
                                            idp_hosts=['idp.example.com'])

        # do the login first
        config = views._load_conf()
        session_id = "a0123456789abcdef0123456789abcdef"
        came_from = '/another-view/'
        saml_response = auth_response({'uid': 'student'}, session_id, config)
        OutstandingQuery.objects.create(session_id=session_id,
                                        came_from=came_from)
        # this will create a user
        response = self.client.post('/acs/', {
                'SAMLResponse': base64.b64encode(str(saml_response)),
                'RelayState': came_from,
                })
        self.assertEquals(response.status_code, 302)

        # now simulate a global logout process initiated by another SP
        subject_id = self.client.session['SAML_SUBJECT_ID']
        instant = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
        saml_request = '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_9961abbaae6d06d251226cb25e38bf8f468036e57e" Version="2.0" IssueInstant="%s" Destination="http://sp.example.com/saml2/ls/"><saml:Issuer>https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml:Issuer><saml:NameID SPNameQualifier="http://sp.example.com/saml2/metadata/" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">%s</saml:NameID><samlp:SessionIndex>_1837687b7bc9faad85839dbeb319627889f3021757</samlp:SessionIndex></samlp:LogoutRequest>' % (
            instant, subject_id)

        response = self.client.get('/ls/', {
                'SAMLRequest': deflate_and_base64_encode(saml_request),
                })
        self.assertEquals(response.status_code, 302)
        location = response['Location']

        url = urlparse.urlparse(location)
        self.assertEquals(url.hostname, 'idp.example.com')
        self.assertEquals(url.path,
                          '/simplesaml/saml2/idp/SingleLogoutService.php')

        params = urlparse.parse_qs(url.query)
        self.assert_('SAMLResponse' in params)

        saml_response = params['SAMLResponse'][0]
        expected_response = """<?xml version='1.0' encoding='UTF-8'?>
<ns0:LogoutResponse Destination="https://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php" ID="a140848e7ce2bce834d7264ecdde0151" InResponseTo="_9961abbaae6d06d251226cb25e38bf8f468036e57e" IssueInstant="2010-09-05T09:10:12Z" Version="2.0" xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"><ns1:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion">http://sp.example.com/saml2/metadata/</ns1:Issuer><ns0:Status><ns0:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></ns0:Status></ns0:LogoutResponse>"""
        xml = decode_base64_and_inflate(saml_response)
        self.assertSAMLRequestsEquals(expected_response, xml)

    def test_metadata(self):
        views._load_conf = conf.create_conf(sp_host='sp.example.com',
                                            idp_hosts=['idp.example.com'])

        valid_until = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        valid_until = valid_until.strftime("%Y-%m-%dT%H:%M:%SZ")
        expected_metadata = """<?xml version='1.0' encoding='UTF-8'?>
<ns0:EntitiesDescriptor validUntil="%s" xmlns:ns0="urn:oasis:names:tc:SAML:2.0:metadata"><ns0:EntityDescriptor entityID="http://sp.example.com/saml2/metadata/" validUntil="%s"><ns0:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><ns0:KeyDescriptor><ns1:KeyInfo xmlns:ns1="http://www.w3.org/2000/09/xmldsig#"><ns1:X509Data><ns1:X509Certificate>MIIDPjCCAiYCCQCkHjPQlll+mzANBgkqhkiG9w0BAQUFADBhMQswCQYDVQQGEwJF
UzEQMA4GA1UECBMHU2V2aWxsYTEbMBkGA1UEChMSWWFjbyBTaXN0ZW1hcyBTLkwu
MRAwDgYDVQQHEwdTZXZpbGxhMREwDwYDVQQDEwh0aWNvdGljbzAeFw0wOTEyMDQx
OTQzNTJaFw0xMDEyMDQxOTQzNTJaMGExCzAJBgNVBAYTAkVTMRAwDgYDVQQIEwdT
ZXZpbGxhMRswGQYDVQQKExJZYWNvIFNpc3RlbWFzIFMuTC4xEDAOBgNVBAcTB1Nl
dmlsbGExETAPBgNVBAMTCHRpY290aWNvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA7rMOMOaIZ/YYD5hYS6Hpjpovcu4k8gaIY+om9zCxLV5F8BLEfkxo
Pk9IA3cRQNRxf7AXCFxEOH3nKy56AIi1gU7X6fCT30JBT8NQlYdgOVMLlR+tjy1b
YV07tDa9U8gzjTyKQHgVwH0436+rmSPnacGj3fMwfySTMhtmrJmax0bIa8EB+gY1
77DBtvf8dIZIXLlGMQFloZeUspvHOrgNoEA9xU4E9AanGnV9HeV37zv3mLDUOQLx
4tk9sMQmylCpij7WZmcOV07DyJ/cEmnvHSalBTcyIgkcwlhmjtSgfCy6o5zuWxYd
T9ia80SZbWzn8N6B0q+nq23+Oee9H0lvcwIDAQABMA0GCSqGSIb3DQEBBQUAA4IB
AQCQBhKOqucJZAqGHx4ybDXNzpPethszonLNVg5deISSpWagy55KlGCi5laio/xq
hHRx18eTzeCeLHQYvTQxw0IjZOezJ1X30DD9lEqPr6C+IrmZc6bn/pF76xsvdaRS
gduNQPT1B25SV2HrEmbf8wafSlRARmBsyUHh860TqX7yFVjhYIAUF/El9rLca51j
ljCIqqvT+klPdjQoZwODWPFHgute2oNRmoIcMjSnoy1+mxOC2Q/j7kcD8/etulg2
XDxB3zD81gfdtT8VBFP+G4UrBa+5zFk6fT6U8a7ZqVsyH+rCXAdCyVlEC4Y5fZri
ID4zT0FcZASGuthM56rRJJSx
</ns1:X509Certificate></ns1:X509Data></ns1:KeyInfo></ns0:KeyDescriptor><ns0:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://sp.example.com/saml2/acs/" index="1" /><ns0:AttributeConsumingService><ns0:ServiceName xml:lang="en">Test SP</ns0:ServiceName><ns0:RequestedAttribute FriendlyName="uid" Name="0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true" /><ns0:RequestedAttribute FriendlyName="eduPersonAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="false" /></ns0:AttributeConsumingService></ns0:SPSSODescriptor><ns0:Organization><ns0:OrganizationName xml:lang="es">Ejemplo S.A.</ns0:OrganizationName><ns0:OrganizationName xml:lang="en">Example Inc.</ns0:OrganizationName><ns0:OrganizationDisplayName xml:lang="es">Ejemplo</ns0:OrganizationDisplayName><ns0:OrganizationDisplayName xml:lang="en">Example</ns0:OrganizationDisplayName><ns0:OrganizationURL xml:lang="es">http://www.example.es</ns0:OrganizationURL><ns0:OrganizationURL xml:lang="en">http://www.example.com</ns0:OrganizationURL></ns0:Organization><ns0:ContactPerson contactType="technical"><ns0:Company>Example Inc.</ns0:Company><ns0:GivenName>Technical givenname</ns0:GivenName><ns0:SurName>Technical surname</ns0:SurName><ns0:EmailAddress>technical@sp.example.com</ns0:EmailAddress></ns0:ContactPerson><ns0:ContactPerson contactType="administrative"><ns0:Company>Example Inc.</ns0:Company><ns0:GivenName>Administrative givenname</ns0:GivenName><ns0:SurName>Administrative surname</ns0:SurName><ns0:EmailAddress>administrative@sp.example.ccom</ns0:EmailAddress></ns0:ContactPerson></ns0:EntityDescriptor></ns0:EntitiesDescriptor>"""

        expected_metadata = expected_metadata % (valid_until, valid_until)

        response = self.client.get('/metadata/')
        self.assertEquals(response['Content-type'], 'text/xml; charset=utf8')
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.content, expected_metadata)

