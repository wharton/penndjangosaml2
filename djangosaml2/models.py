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

from django.db import models


class OutstandingQueryManager(models.Manager):

    def as_dict(self):
        return dict([(oq.session_id, oq.came_from) for oq in self.all()])

    def clear_session(self, session_id):
        if session_id:
            try:
                oq = self.get(session_id=session_id)
                oq.delete()
            except OutstandingQuery.DoesNotExist:
                pass


class OutstandingQuery(models.Model):
    """Queries that were made to an IdP and are not yet replied"""

    session_id = models.CharField("PySAML2 session",
                                  max_length=100, blank=False)
    came_from = models.CharField("PySAML2 rely state",
                                 max_length=200, blank=False)
    creation_time = models.DateTimeField(auto_now=True)

    objects = OutstandingQueryManager()

    def __unicode__(self):
        return u'%s - %s' % (self.session_id, self.come_from)
