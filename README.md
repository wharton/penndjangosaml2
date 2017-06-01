# penndjangosaml2

penndjangosaml2 is a fork of djangosaml2 that incorporates Penn specific saml settings. This library allows python/django applications to utilize University of Pennsylvania's IdP (Identity Provider) for authentication. It also incorporates Penn Groups for basic permissions and authorization.

## Installation & Getting Started

1. PySAML2 uses xmlsec1 binary to sign SAML assertions so you need to install it either through your operating system package manager or by compiling the source code. You can download xmlsec1 from http://www.aleksey.com/xmlsec/. Just make sure you install it under `/usr/bin/xmlsec1`. If you're Wharton Computing Staff, you can use our [pre-built vagrant environment](https://stash.wharton.upenn.edu/projects/VAGRANT/repos/python-dev). Wharton's python/django app servers already have the dependency installed.
2. Add the following to your requirements.txt file (or install from CLI via pip): `git+https://github.com/wharton/penndjangosaml2.git`

## Configuration

There are two items you need to setup to make penndjangosaml2 work in your Django project:

1. **settings.py** as you may already know, it is the main Django configuration file. Note that your main settings file might be located somewhere different (i.e. settings/base.py)
2. **urls.py** is the file where you will include penndjangosaml2 urls.

## Changes in the settings.py file

The first thing you need to do is add `penndjangosaml2` to the list of installed apps::

``` python
    INSTALLED_APPS = (
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.sites',
        'django.contrib.messages',
        'django.contrib.admin',
        'penndjangosaml2', # new application
    )
```

Then you have to add the `penndjangosaml2.backends.Saml2Backend` authentication backend to the list of authentications backends. By default only the ModelBackend included in Django is configured. A typical configuration would look like this::

``` python
    AUTHENTICATION_BACKENDS
        'django.contrib.auth.backends.ModelBackend',
        'penndjangosaml2.backends.Saml2Backend',
    )
```

#### Private key and public certificate

pysaml2 uses a key/pair to encrypt/sign assertions. For Wharton Computing folks, these are currently generated on cdl-django0101 (csl-django0101 and cpl will be updated soon); however, if you are running locally in vagrant you will either need to provide a location to your self-signed key/certs or generate them directly in `/etc/shibboleth/pki/shibcert|key.pem`.

To generate your own, run the following: `openssl req -x509 -newkey rsa:4096 -keyout shibkey.pem -out shibcert.pem -days 365 -nodes -sha256` and answer the resulting prompts.

The settings for providing your own are (you can omit these if deploying to cdl-django0101):

``` python
    CERT_FILE = '/absolute/path/to/certfile.pem
    KEY_FILE = '/absolute/path/to/keyfile.pem
```

Finally we have to let Django know of a few additional settings:

``` python
    PATH_NAME = '/<your_url_path_name>'
    LOGIN_URL = PATH_NAME + '/saml2/login/'
    LOGOUT_URL = PATH_NAME + '/penn-logout/'
```

`PATH_NAME` is the trailing path in your URL (i.e. /shoutouts).
If you do not have a `PATH_NAME`, just leave it completely blank.

Here we are telling Django that any view that requires an authenticated user should redirect the client browser to the login/authentication url if the user has not been authenticated before. We are also telling Django that when the user closes his browser, the session should be terminated. This is useful in SAML2 federations where the logout protocol is not always available.

#### Note

The login url starts with `/saml2/` as an example but you can change that if you want. Check the section about changes in the `urls.py` file for more information.

If you want to allow several authentication mechanisms in your project you should set the LOGIN_URL option to another view and put a link in such view to the `/saml2/login/` view.

## Changes in the urls.py file

The next thing you need to do is to include `penndjangosaml2.urls` module to your main `urls.py` module::

``` python
    urlpatterns = patterns( '',
        #  lots of url definitions here

        url(r'^saml2/', include('penndjangosaml2.urls')),

        #  more url definitions
    )
```

# Adding your service provider metadata to Penn's identity provider
#### This step requires ISC approval.

1. Once you have your application up and running, visit `http://<your server name>/<path name>/saml2/metadata`. For example, https://cdl-django0101.wharton.upenn.edu/shibboleth/saml2/metadata.
2. Save the resulting XML output as a txt file.
3. Email ISC at weblogin-tech@isc.upenn.edu and ask them to add your SP's metadata to their IdP (don't forget to attach the saved XML as txt file).
4. Turnaround time for a response is typically 1 to 3 business days. Project timing and management needs to account for this.

#### Note on the above approval process
Be aware that you will need to do this for each new application and for every stage of development for said application. If you are developing an application that has local dev for testing and three stages of deployment (develop, stage, and production), you will need ISC to add four metadata files.

Example URL structure:
1. `https://vagrant.wharton.upenn.edu/<app name>/saml2/metadata` **(local vagrant development)**
2. `https://<dev server>.wharton.upenn.edu/<app name>/saml2/metadata` **(develop)**
3. `https://<stage server>.wharton.upenn.edu/<app name>/saml2/metadata` **(staging)**
4. `https://apps.wharton.upenn.edu/<app name>/saml2/metadata` **(production)**

# Authentication & Authorization
penndjangosaml2 module allows for protecting individual views with decorators and mixins. It also includes [django-braces](https://django-braces.readthedocs.io/en/latest/) by default, which gives you more granular authorization at the group and permission level.

The user will be redirected back to the LOGIN_URL for all unauthorized or unauthenticated requests that are protected with a decorator or mixin

## Authentication
There are two ways to protect a django view behind login required. For a function-based view, use the [login required decorator](https://docs.djangoproject.com/en/1.11/topics/auth/default/#the-login-required-decorator). For class-based views, you can use the [login required mixin](https://docs.djangoproject.com/en/1.11/topics/auth/default/#the-loginrequired-mixin).

## Authorization
penndjangosaml2 will attempt to populate a user's groups in django with a default set from Penn Groups. This default set includes **penn:community:staff** and **penn:community:employee**. If you would like additional groups to authorize against, add them as a list in your settings file.

``` python
    INCLUDE_PENN_GROUPS = ('penn:wharton:apps:<app_name>', 'penn:community:alumni',)
```

Using django-braces we can then assert that the user should be a part of one of those groups when requesting a service. For example:

``` python
from django.views.generic import TemplateView

from braces.views import GroupRequiredMixin


class SomeProtectedView(GroupRequiredMixin, TemplateView):
    group_required = 'penn:community:staff'
    template_name = 'protected.html'
```

Please see more here from django-braces [GroupRequiredMixin](https://django-braces.readthedocs.io/en/latest/access.html#grouprequiredmixin) documentation.

For more granular object level permissions, you can use django's built-in [permission required decorator](https://docs.djangoproject.com/en/1.11/topics/auth/default/#the-permission-required-decorator) for function-based views or for class-based views, you can use the [permission required mixin](https://docs.djangoproject.com/en/1.11/topics/auth/default/#the-permissionrequiredmixin-mixin)

django-braces also allows for some more powerful level of [permission authorization](https://django-braces.readthedocs.io/en/latest/access.html#permissionrequiredmixin).

# Test Application
If you are Wharton Computing Staff, there is an application that can be used for testing. You must have [vagrant](https://stash.wharton.upenn.edu/projects/VAGRANT/repos/python-dev/browse) installed first. After you're up an running with vagrant, clone [this repo](https://stash.wharton.upenn.edu/projects/CAOS/repos/django_penn_shibboleth/browse) and follow the instructions in the README.
