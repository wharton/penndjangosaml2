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

import re
import urlparse

from django.test import TestCase

from saml2.s_utils import decode_base64_and_inflate

from djangosaml2 import views
from djangosaml2.tests import conf

class SSOTests(TestCase):

    urls = 'djangosaml2.urls'

    def assertSAMLRequestsEquals(self, xml1, xml2):
        def remove_variable_attributes(xml_string):
            xml_string = re.sub(r' ID=".*" ', ' ', xml_string)
            xml_string = re.sub(r' IssueInstant=".*" ', ' ', xml_string)
            return xml_string

        self.assertEquals(remove_variable_attributes(xml1),
                          remove_variable_attributes(xml2))

    def test_login(self):
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
