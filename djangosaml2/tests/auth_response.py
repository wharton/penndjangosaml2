# Copyright (C) 2011 Yaco Sistemas (http://www.yaco.es)
# Copyright (C) 2010 Lorenzo Gil Sanchez <lorenzo.gil.sanchez@gmail.com>
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

import os

from saml2 import saml, class_name
from saml2.config import IDPConfig
from saml2.assertion import Assertion
from saml2.s_utils import response_factory, sid
from saml2.s_utils import success_status_factory
from saml2.sigver import signed_instance_factory, pre_signature_part
from saml2.sigver import security_context

BASEDIR = os.path.dirname(os.path.abspath(__file__))


def auth_response(identity, in_response_to, sp_conf):
    """Generates a fresh signed authentication response"""
    sp_entity_id = sp_conf['entityid']
    idp_entity_id = sp_conf['service']['sp']['idp'].keys()[0]
    acs = sp_conf.endpoint('sp', 'assertion_consumer_service')[0]
    attribute_converters = sp_conf.attribute_converters()
    issuer = saml.Issuer(text=idp_entity_id, format=saml.NAMEID_FORMAT_ENTITY)
    response = response_factory(issuer=issuer,
                                in_response_to=in_response_to,
                                destination=acs,
                                status=success_status_factory())
    idp_conf = IDPConfig()
    name_form = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    idp_conf.load({
            'entityid': idp_entity_id,
            'xmlsec_binary': sp_conf['xmlsec_binary'],
            'attribute_map_dir': sp_conf['attribute_map_dir'],
            'service': {
                'idp': {
                    'endpoints': tuple(),
                    'policy':  {
                        'default': {
                            "lifetime": {"minutes": 15},
                            "attribute_restrictions": None,
                            "name_form": name_form,
                            }
                        }
                    },
                },
            'key_file': os.path.join(BASEDIR, 'idpcert.key'),
            'cert_file': os.path.join(BASEDIR, 'idpcert.pem'),
            'metadata': '',
            })

    ast = Assertion(identity)
    policy = idp_conf.idp_policy()
    ast.apply_policy(sp_entity_id, policy, {})
    name_id = saml.NameID(format=saml.NAMEID_FORMAT_TRANSIENT,
                          text=sid())

    authn_class = saml.AUTHN_PASSWORD
    authn_authn = 'http://idp.example.com/login/'
    assertion = ast.construct(sp_entity_id, in_response_to, acs,
                              name_id, attribute_converters, policy,
                              issuer=issuer,
                              authn_class=authn_class,
                              authn_auth=authn_authn)

    sec = security_context(idp_conf)

    assertion.signature = pre_signature_part(assertion.id, sec.my_cert, 1)
    to_sign = [(class_name(assertion), assertion.id)]
    response.assertion = assertion
    return signed_instance_factory(response, sec, to_sign)
