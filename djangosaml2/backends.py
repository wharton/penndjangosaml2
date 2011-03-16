# Copyright (C) 2010-2011 Yaco Sistemas (http://www.yaco.es)
# Copyright (C) 2009 Lorenzo Gil Sanchez <lorenzo.gil.sanchez@gmail.com>
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

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User


class Saml2Backend(ModelBackend):
    """This backend is added automatically by the assertion_consumer_service
    view.

    Don't add it to settings.AUTHENTICATION_BACKENDS.
    """

    def authenticate(self, session_info=None, attribute_mapping=None,
                     create_unknown_user=True):
        if session_info is None or attribute_mapping is None:
            return None

        if not 'ava' in session_info:
            return None

        attributes = session_info['ava']
        try:
            reverse_mapping = dict([(v, k)
                                    for k, v in attribute_mapping.items()])
            saml_user = attributes[reverse_mapping['username']][0]
        except KeyError:
            return None

        user = None
        username = self.clean_username(saml_user)

        # Note that this could be accomplished in one try-except clause, but
        # instead we use get_or_create when creating unknown users since it has
        # built-in safeguards for multiple threads.
        if create_unknown_user:
            user, created = User.objects.get_or_create(username=username)
            if created:
                user = self.configure_user(user, attributes, attribute_mapping)
            else:
                user = self.update_user(user, attributes, attribute_mapping)
        else:
            try:
                user = User.objects.get(username=username)
                user = self.update_user(user, attributes, attribute_mapping)
            except User.DoesNotExist:
                pass

        return user

    def clean_username(self, username):
        """Performs any cleaning on the "username" prior to using it to get or
        create the user object.  Returns the cleaned username.

        By default, returns the username unchanged.
        """
        return username

    def configure_user(self, user, attributes, attribute_mapping):
        """Configures a user after creation and returns the updated user.

        By default, returns the user unmodified.
        """
        return user

    def update_user(self, user, attributes, attribute_mapping):
        """Update a user with a set of attributes and returns the updated user.

        By default it uses a mapping defined in the settings constant
        SAML_ATTRIBUTE_MAPPING.
        """
        if not attribute_mapping:
            return user

        modified = False
        for saml_attr, django_attr in attribute_mapping.items():
            try:
                setattr(user, django_attr, attributes[saml_attr][0])
                modified = True
            except KeyError:
                # the saml attribute is missing
                pass

        if modified:
            user.save()

        return user
