from django.conf import settings

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED
from socket import gethostname

import os


CWD = os.path.dirname(os.path.realpath(__file__))

HOST_NAME = gethostname()

PATH_NAME = getattr(
    settings, 'PATH_NAME', '')

BASE_URI = 'https://' + HOST_NAME + PATH_NAME

SAML_DJANGO_USER_MAIN_ATTRIBUTE = getattr(
    settings, 'SAML_DJANGO_USER_MAIN_ATTRIBUTE', 'username')

SAML_DJANGO_USER_MAIN_ATTRIBUTE_LOOKUP = getattr(
    settings, 'SAML_DJANGO_USER_MAIN_ATTRIBUTE_LOOKUP', '')

SESSION_EXPIRE_AT_BROWSER_CACHE = getattr(
    settings, 'SESSION_EXPIRE_AT_BROWSER_CACHE', True)

SAML_CONFIG_DEFAULT = {
    'xmlsec_binary': '/usr/bin/xmlsec1',
    'entityid': BASE_URI + '/saml2/metadata/',
    'service': {
        'sp' : {
            'name': 'Penn Django Shibboleth Authentication',
            'endpoints': {
                'assertion_consumer_service': [
                    (BASE_URI + '/saml2/acs/', BINDING_HTTP_POST),
                ],
                'single_logout_service': [
                    (BASE_URI + '/saml2/ls/', BINDING_HTTP_REDIRECT),
                    (BASE_URI + '/saml2/ls/post/', BINDING_HTTP_POST),
                ],
            },
            'required_attributes': ['eduPersonAffiliation','eduPersonPrincipalName'],
            'optional_attributes': ['sn','givenName','mail'],
        },
    },
    'metadata': {
        'local': [os.path.join(CWD, 'assets/metadata.xml')],
    },
    'debug': 1,
    'key_file': os.path.join(CWD, 'pki/shibkey.pem'),
    'cert_file': os.path.join(CWD, 'pki/shibcert.pem'),
    'encryption_keypairs': [{
        'key_file': os.path.join(CWD, 'pki/shibkey.pem'),
        'cert_file': os.path.join(CWD, 'pki/shibcert.pem'),
    }],
    'contact_person': [
        {
            'given_name': 'Stephen',
            'sur_name': 'Turoscy',
            'company': 'The Wharton School',
            'email_address': 'sturoscy@wharton.upenn.edu',
            'contact_type': 'technical'
        },
    ],
    'organization': {
        'name': [('UPenn', 'en')],
        'display_name': [('Upenn', 'en')],
        'url': [('http://www.upenn.edu', 'en')],
    },
}

SAML_CONFIG = getattr(
    settings, 'SAML_CONFIG', SAML_CONFIG_DEFAULT)

SAML_CREATE_UNKNOWN_USER = getattr(
    settings, 'SAML_CREATE_UNKNOWN_USER', True)

SAML_ATTRIBUTE_MAPPING_DEFAULT = {
    'eduPersonPrincipalName': 'username',
    'mail': ('email', ),
    'givenName': ('first_name', ),
    'sn': ('last_name', ),
}

SAML_ATTRIBUTE_MAPPING = getattr(
    settings, 'SAML_ATTRIBUTE_MAPPING', SAML_ATTRIBUTE_MAPPING_DEFAULT)
