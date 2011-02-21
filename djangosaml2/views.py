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

from django.conf import settings
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import logout as django_logout
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
try:
    from django.views.decorators.csrf import csrf_exempt
except ImportError:
    # Django 1.0 compatibility
    def csrf_exempt(view_func):
        return view_func

from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.metadata import entity_descriptor, entities_descriptor
from saml2.sigver import SecurityContext

from djangosaml2.cache import IdentityCache, OutstandingQueriesCache
from djangosaml2.cache import StateCache
from djangosaml2.conf import config_settings_loader


def _set_subject_id(session, subject_id):
    session['_saml2_subject_id'] = subject_id


def _get_subject_id(session):
    return session['_saml2_subject_id']


def login(request, config_loader=config_settings_loader):
    """SAML Authorization Request initiator

    This view initiates the SAML2 Authorization handshake
    using the pysaml2 library to create the AuthnRequest.
    It uses the SAML 2.0 Http Redirect protocol binding.
    """
    came_from = request.GET.get('next', '/')
    selected_idp = request.GET.get('idp', None)
    conf = config_loader()
    if selected_idp is None and conf.is_wayf_needed():
        return render_to_response('djangosaml2/wayf.html', {
                'available_idps': conf.get_available_idps(),
                'came_from': came_from,
                }, context_instance=RequestContext(request))

    if selected_idp is not None:
        selected_idp = conf.single_sign_on_service(selected_idp)

    client = Saml2Client(conf)
    (session_id, result) = client.authenticate(
        location=selected_idp, relay_state=came_from,
        binding=BINDING_HTTP_REDIRECT,
        )
    assert len(result) == 2
    assert result[0] == 'Location'
    location = result[1]

    oq_cache = OutstandingQueriesCache(request.session)
    oq_cache.set(session_id, came_from)

    return HttpResponseRedirect(location)


@csrf_exempt
def assertion_consumer_service(request, config_loader=config_settings_loader):
    """SAML Authorization Response endpoint

    The IdP will send its response to this view, which
    will process it with pysaml2 help and log the user
    in using the custom Authorization backend
    djangosaml2.backends.Saml2Backend that should be
    enabled in the settings.py
    """
    conf = config_loader()
    post = {'SAMLResponse': request.POST['SAMLResponse']}
    client = Saml2Client(conf, identity_cache=IdentityCache(request.session))

    oq_cache = OutstandingQueriesCache(request.session)
    outstanding_queries = oq_cache.outstanding_queries()

    # process the authentication response
    response = client.response(post, conf['entityid'], outstanding_queries)
    if response is None:
        return HttpResponse("SAML response has errors. Please check the logs")

    session_id = response.session_id()
    oq_cache.delete(session_id)

    # authenticate the remote user
    session_info = response.session_info()

    if 'djangosaml2.backends.Saml2Backend' not in settings.AUTHENTICATION_BACKENDS:
        settings.AUTHENTICATION_BACKENDS = (('djangosaml2.backends.Saml2Backend', )
                                            + settings.AUTHENTICATION_BACKENDS)

    user = auth.authenticate(session_info=session_info)
    if user is None:
        return HttpResponse("user not valid")

    auth.login(request, user)
    _set_subject_id(request.session, session_info['name_id'])

    # redirect the user to the view where he came from
    relay_state = request.POST.get('RelayState', '/')
    return HttpResponseRedirect(relay_state)


@login_required
def logout(request, config_loader=config_settings_loader):
    """SAML Logout Request initiator

    This view initiates the SAML2 Logout request
    using the pysaml2 library to create the LogoutRequest.
    """
    state = StateCache(request.session)
    client = Saml2Client(config_loader(), state_cache=state,
                         identity_cache=IdentityCache(request.session))
    subject_id = _get_subject_id(request.session)
    session_id, code, head, body = client.global_logout(subject_id)
    headers = dict(head)
    state.sync()
    return HttpResponseRedirect(headers['Location'])


def logout_service(request, config_loader=config_settings_loader):
    """SAML Logout Response endpoint

    The IdP will send the logout response to this view,
    which will process it with pysaml2 help and log the user
    out.
    Note that the IdP can request a logout even when
    we didn't initiate the process as a single logout
    request started by another SP.
    """
    conf = config_loader()
    state = StateCache(request.session)
    client = Saml2Client(conf, state_cache=state,
                         identity_cache=IdentityCache(request.session))

    if 'SAMLResponse' in request.GET:  # we started the logout
        response = client.logout_response(request.GET['SAMLResponse'],
                                          binding=BINDING_HTTP_REDIRECT)
        state.sync()
        if response and response[1] == '200 Ok':
            return django_logout(request)
        else:
            return HttpResponse('Error during logout')

    elif 'SAMLRequest' in request.GET:  # logout started by the IdP
        subject_id = _get_subject_id(request.session)
        response, success = client.logout_request(request.GET, subject_id)
        state.sync()
        if success:
            auth.logout(request)
            assert response[0][0] == 'Location'
            url = response[0][1]
            return HttpResponseRedirect(url)
        elif response is not None:
            assert response[0][0] == 'Location'
            url = response[0][1]
            return HttpResponseRedirect(url)
        else:
            return HttpResponse('Error during logout')
    else:
        raise Http404('No SAMLResponse or SAMLRequest parameter found')


def metadata(request, config_loader=config_settings_loader, sign=False):
    """Returns an XML with the SAML 2.0 metadata for this
    SP as configured in the settings.py file.
    """
    conf = config_loader()
    valid_for = conf.get('valid_for', 24)
    output = entities_descriptor([entity_descriptor(conf, valid_for)],
                                 valid_for, conf.name(), conf['entityid'],
                                 sign, SecurityContext(conf.xmlsec(),
                                                       conf['key_file']))
    return HttpResponse(content=str(output),
                        content_type="text/xml; charset=utf8")
