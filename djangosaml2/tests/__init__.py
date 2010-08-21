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

from django.test import TestCase

from djangosaml2 import views
from djangosaml2.tests import conf

class SSOTests(TestCase):

    urls = 'djangosaml2.urls'

    def test_login(self):
        # monkey patch SAML configuration
        views._load_conf = conf.create_conf()

        response = self.client.get('/login/')
        self.assertEquals(response.status_code, 302)
        location = response['Location']
        print location
