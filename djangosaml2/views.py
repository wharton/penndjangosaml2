# Copyright (C) 2010 Yaco Sistemas (http://www.yaco.es)
# Copyright (C) 2009 Lorenzo Gil Sanchez
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

import copy
import urllib

from django.conf import settings
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import logout as django_logout
from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt

from saml2.client import Saml2Client
from saml2.config import Config
from saml2.metadata import entity_descriptor, entities_descriptor
from saml2.sigver import SecurityContext
from saml2.utils import deflate_and_base64_encode

from djangosaml2.models import OutstandingQuery


def _load_conf():
    """Utility function to load the pysaml2 configuration"""
    conf = Config()
    conf.load(copy.deepcopy(settings.SAML_CONFIG))
    return conf


def login(request):
    """SAML Authorization Request initiator

    This view initiates the SAML2 Authorization handshake
    using the pysaml2 library to create the AuthnRequest.
    It uses the SAML 2.0 Http Redirect protocol binding.
    """
    came_from = request.GET.get('next', '/')
    conf = _load_conf()
    srv = conf['service']['sp']
    idp_url = srv['idp'].values()[0]['sso_service']
    client = Saml2Client(None, conf)

    (session_id, result) = client.authenticate(
        spentityid=conf['entityid'],
        location=idp_url,
        service_url=srv['url'],
        my_name=srv['name'],
        relay_state=came_from)

    OutstandingQuery.objects.create(session_id=session_id,
                                    came_from=came_from)

    redirect_url = result[1]
    return HttpResponseRedirect(redirect_url)


@csrf_exempt
def assertion_consumer_service(request):
    """SAML Authorization Response endpoint

    The IdP will send its response to this view, which
    will process it with pysaml2 help and log the user
    in using the custom Authorization backend
    djangosaml2.backends.Saml2Backend that should be
    enabled in the settings.py
    """
    conf = _load_conf()
    post = {'SAMLResponse': request.POST['SAMLResponse']}
    client = Saml2Client(None, conf)
    response = client.response(post, conf['entityid'],
                               OutstandingQuery.objects.as_dict())
    session_id = response.session_id()
    session_info = response.session_info()
    OutstandingQuery.objects.clear_session(session_id)

    user = auth.authenticate(session_info=session_info)
    if user is None:
        return HttpResponse("user not valid")

    auth.login(request, user)
    request.session['SAML_SESSION_ID'] = session_id
    request.session['SAML_SUBJECT_ID'] = session_info['name_id']
    relay_state = request.POST.get('RelayState', '/')
    return HttpResponseRedirect(relay_state)


@login_required
def logout(request):
    """SAML Logout Request initiator

    This view initiates the SAML2 Logout request
    using the pysaml2 library to create the LogoutRequest.
    """
    conf = _load_conf()
    srv = conf['service']['sp']
    idp_url = srv['idp'].values()[0]['logout_service']
    client = Saml2Client(None, conf)
    session_id = request.session['SAML_SESSION_ID']
    subject_id = request.session['SAML_SUBJECT_ID']
    logout_req = client.logout(session_id,
                               destination=idp_url,
                               issuer=conf['entityid'],
                               subject_id=subject_id)

    print logout_req
    arg = urllib.quote_plus(deflate_and_base64_encode(str(logout_req)))
    redirect_url = "%s?SAMLRequest=%s" % (idp_url, arg)

    return HttpResponseRedirect(redirect_url)


def logout_service(request):
    """SAML Logout Response endpoint

    The IdP will send the logout response to this view,
    which will process it with pysaml2 help and log the user
    out.
    Note that the IdP can request a logout even when
    we didn't initiate the process as a single logout
    request started by another SP.
    """
    client = Saml2Client(None, _load_conf())
    success = client.logout_response(request.GET)
    if success:
        return django_logout(request)
    else:
        return HttpResponse('Error during logout')


def metadata(request):
    """Returns an XML with the SAML 2.0 metadata for this
    SP as configured in the settings.py file.
    """
    ed_id = getattr(settings, 'SAML_METADATA_ID', '')
    name = getattr(settings, 'SAML_METADATA_NAME', '')
    sign = getattr(settings, 'SAML_METADATA_SIGN', False)
    conf = _load_conf()
    valid_for = conf.get('valid_for', 24)
    output = entities_descriptor([entity_descriptor(conf, valid_for)],
                                 valid_for, name, ed_id, sign,
                                 SecurityContext(conf.xmlsec(),
                                                 conf['key_file']))
    return HttpResponse(content=output, content_type="text/xml; charset=utf8")
