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

SAML2_SESSION_PREFIX = '_saml2'


class OutstandingQueriesCache(object):
    """Class that manages the queries that have been sent to the IdP
    and have not been replied yet.

    This implementation store the queries in the Django session.
    """

    def __init__(self, django_session):
        self.session = django_session
        self.session_key = SAML2_SESSION_PREFIX + '_outstanding_queries'

    def get_queries(self):
        return self.session.get(self.session_key, {})

    def set_queries(self, outstanding_queries):
        self.session[self.session_key] = outstanding_queries

    def add_query(self, saml2_session_id, came_from):
        outstanding_queries = self.get_queries()
        outstanding_queries[saml2_session_id] = came_from
        self.set_queries(outstanding_queries)

    def del_query(self, saml2_session_id):
        outstanding_queries = self.get_queries()
        if saml2_session_id in outstanding_queries:
            del outstanding_queries[saml2_session_id]
            self.set_queries(outstanding_queries)
