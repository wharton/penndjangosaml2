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

import os.path

from saml2.config import Config


def create_conf(sp_host='sp.example.com', idp_hosts=['idp.example.com']):

    def _load_conf():
        BASEDIR = os.path.dirname(os.path.abspath(__file__))
        config = {
            'xmlsec_binary': '/usr/bin/xmlsec1',
            'entityid': 'http://%s/saml2/metadata/' % sp_host,
            'attribute_map_dir': os.path.join(BASEDIR, 'attribute-maps'),

            'service': {
                'sp': {
                    'name': 'Test SP',
                    'endpoints': {
                        'assertion_consumer_service': ['http://%s/saml2/acs/' %
                                                       sp_host],
                        'logout_service': ['http://%s/saml2/ls/' % sp_host],
                        },
                    'required_attributes': ['uid'],
                    'optional_attributes': ['eduPersonAffiliation'],
                    'idp': {}  # this is filled later
                    },
                },

            'metadata': {
                'local': [os.path.join(BASEDIR, 'remote_metadata.xml')],
                },

            'debug': 1,

            # certificates
            'key_file': os.path.join(BASEDIR, 'mycert.key'),
            'cert_file': os.path.join(BASEDIR, 'mycert.pem'),

            # These fields are only used when generating the metadata
            'contact_person': [
                {'givenname': 'Technical givenname',
                 'surname': 'Technical surname',
                 'company': 'Example Inc.',
                 'mail': 'technical@sp.example.com',
                 'type': 'technical'},
                {'givenname': 'Administrative givenname',
                 'surname': 'Administrative surname',
                 'company': 'Example Inc.',
                 'mail': 'administrative@sp.example.ccom',
                 'type': 'administrative'},
                ],
            'organization': {
                'name': [('Example Inc.', 'es'), ('Example Inc.', 'en')],
                'display_name': ['Example'],
                'url': [('http://www.example.com', 'es'),
                        ('http://www.example.com', 'en')],
                },
            'valid_for': 24,  # hours
            }

        for idp in idp_hosts:
            entity_id = 'https://%s/simplesaml/saml2/idp/metadata.php' % idp
            config['service']['sp']['idp'][entity_id] = {
                'sso_service': 'https://%s/simplesaml/saml2/idp/SSOService.php' % idp,
                'logout_service': 'https://%s/simplesaml/saml2/idp/SingleLogoutService.php' % idp,
                }

        saml_conf = Config()
        saml_conf.load(config)
        return saml_conf

    return _load_conf
