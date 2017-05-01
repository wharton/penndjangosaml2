# djangosaml2

## PySAML2 specific files and configuration

Once you have finished configuring your Django project you have to start configuring PySAML. If you use just that library you have to put your configuration options in a file and initialize PySAML2 with the path to that file.

In djangosaml2 you just put the same information in the Django settings.py file under the SAML_CONFIG option.

We will see a typical configuration for protecting a Django project::

from os import path import saml2 import saml2.saml BASEDIR = path.dirname(path.abspath(**file**)) SAML_CONFIG = {

```
# full path to the xmlsec1 binary programm
'xmlsec_binary': '/usr/bin/xmlsec1',

# your entity id, usually your subdomain plus the url to the metadata view
'entityid': 'http://localhost:8000/saml2/metadata/',

# directory with attribute mapping
'attribute_map_dir': path.join(BASEDIR, 'attribute-maps'),

# this block states what services we provide
'service': {
    # we are just a lonely SP
    'sp' : {
        'name': 'Federated Django sample SP',
        'name_id_format': saml2.saml.NAMEID_FORMAT_PERSISTENT,
        'endpoints': {
            # url and binding to the assetion consumer service view
            # do not change the binding or service name
            'assertion_consumer_service': [
                ('http://localhost:8000/saml2/acs/',
                 saml2.BINDING_HTTP_POST),
                ],
            # url and binding to the single logout service view
            # do not change the binding or service name
            'single_logout_service': [
                ('http://localhost:8000/saml2/ls/',
                 saml2.BINDING_HTTP_REDIRECT),
                ('http://localhost:8000/saml2/ls/post',
                 saml2.BINDING_HTTP_POST),
                ],
            },

         # attributes that this project need to identify a user
        'required_attributes': ['uid'],

         # attributes that may be useful to have but not required
        'optional_attributes': ['eduPersonAffiliation'],

        # in this section the list of IdPs we talk to are defined
        'idp': {
            # we do not need a WAYF service since there is
            # only an IdP defined here. This IdP should be
            # present in our metadata

            # the keys of this dictionary are entity ids
            'https://localhost/simplesaml/saml2/idp/metadata.php': {
                'single_sign_on_service': {
                    saml2.BINDING_HTTP_REDIRECT: 'https://localhost/simplesaml/saml2/idp/SSOService.php',
                    },
                'single_logout_service': {
                    saml2.BINDING_HTTP_REDIRECT: 'https://localhost/simplesaml/saml2/idp/SingleLogoutService.php',
                    },
                },
            },
        },
    },

# where the remote metadata is stored
'metadata': {
    'local': [path.join(BASEDIR, 'remote_metadata.xml')],
    },

# set to 1 to output debugging information
'debug': 1,

# Signing
'key_file': path.join(BASEDIR, 'mycert.key'),  # private part
'cert_file': path.join(BASEDIR, 'mycert.pem'),  # public part

# Encryption
'encryption_keypairs': [{
    'key_file': path.join(BASEDIR, 'my_encryption_key.key'),  # private part
    'cert_file': path.join(BASEDIR, 'my_encryption_cert.pem'),  # public part
}],

# own metadata settings
'contact_person': [
    {'given_name': 'Lorenzo',
     'sur_name': 'Gil',
     'company': 'Yaco Sistemas',
     'email_address': 'lgs@yaco.es',
     'contact_type': 'technical'},
    {'given_name': 'Angel',
     'sur_name': 'Fernandez',
     'company': 'Yaco Sistemas',
     'email_address': 'angel@yaco.es',
     'contact_type': 'administrative'},
    ],
# you can set multilanguage information here
'organization': {
    'name': [('Yaco Sistemas', 'es'), ('Yaco Systems', 'en')],
    'display_name': [('Yaco', 'es'), ('Yaco', 'en')],
    'url': [('http://www.yaco.es', 'es'), ('http://www.yaco.com', 'en')],
    },
'valid_for': 24,  # how long is our metadata valid
}
```

.. note::

Please check the `PySAML2 documentation`_ for more information about these and other configuration options.

.. _`PySAML2 documentation`: <http://packages.python.org/pysaml2/>

There are several external files and directories you have to create according to this configuration.

The xmlsec1 binary was mentioned in the installation section. Here, in the configuration part you just need to put the full path to xmlsec1 so PySAML2 can call it as it needs.

The `attribute_map_dir` points to a directory with attribute mappings that are used to translate user attribute names from several standards. It's usually safe to just copy the default PySAML2 attribute maps that you can find in the `tests/attributemaps` directory of the source distribution.

The `metadata` option is a dictionary where you can define several types of metadata for remote entities. Usually the easiest type is the `local` where you just put the name of a local XML file with the contents of the remote entities metadata. This XML file should be in the SAML2 metadata format.

The `key_file` and `cert_file` options references the two parts of a standard x509 certificate. You need it to sign your metadata an to encrypt and decrypt the SAML2 assertions.

.. note::

Check your openssl documentation to generate a test certificate but don't forget to order a real one when you go into production.

Custom and dynamic configuration loading ........................................

By default, djangosaml2 reads the pysaml2 configuration options from the SAML_CONFIG setting but sometimes you want to read this information from another place, like a file or a database. Sometimes you even want this configuration to be different depending on the request.

Starting from djangosaml2 0.5.0 you can define your own configuration loader which is a callable that accepts a request parameter and returns a saml2.config.SPConfig object. In order to do so you set the following setting::

SAML_CONFIG_LOADER = 'python.path.to.your.callable'

## User attributes

In the SAML 2.0 authentication process the Identity Provider (IdP) will send a security assertion to the Service Provider (SP) upon a succesful authentication. This assertion contains attributes about the user that was authenticated. It depends on the IdP configuration what exact attributes are sent to each SP it can talk to.

When such assertion is received on the Django side it is used to find a Django user and create a session for it. By default djangosaml2 will do a query on the User model with the 'username' attribute but you can change it to any other attribute of the User model. For example, you can do this look up using the 'email' attribute. In order to do so you should set the following setting::

SAML_DJANGO_USER_MAIN_ATTRIBUTE = 'email'

Please, use an unique attribute when setting this option. Otherwise the authentication process will fail because djangosaml2 does not know which Django user it should pick.

If your main attribute is something inherently case-inensitive (such as an email address), you may set::

SAML_DJANGO_USER_MAIN_ATTRIBUTE_LOOKUP = '__iexact'

(This is simply appended to the main attribute name to form a Django query. Your main attribute must be unique even given this lookup.)

Another option is to use the SAML2 name id as the username by setting::

SAML_USE_NAME_ID_AS_USERNAME = True

You can configure djangosaml2 to create such user if it is not already in the Django database or maybe you don't want to allow users that are not in your database already. For this purpose there is another option you can set in the settings.py file::

SAML_CREATE_UNKNOWN_USER = True

This setting is True by default.

ACS_DEFAULT_REDIRECT_URL = reverse_lazy('some_url_name')

This setting lets you specify a URL for redirection after a successful authentication. Particularly useful when you only plan to use IdP initiated login and the IdP does not have a configured RelayState parameter. The default is `/`.

The other thing you will probably want to configure is the mapping of SAML2 user attributes to Django user attributes. By default only the User.username attribute is mapped but you can add more attributes or change that one. In order to do so you need to change the SAML_ATTRIBUTE_MAPPING option in your settings.py::

SAML_ATTRIBUTE_MAPPING = { 'uid': ('username', ), 'mail': ('email', ), 'cn': ('first_name', ), 'sn': ('last_name', ), }

where the keys of this dictionary are SAML user attributes and the values are Django User attributes.

If you are using Django user profile objects to store extra attributes about your user you can add those attributes to the SAML_ATTRIBUTE_MAPPING dictionary. For each (key, value) pair, djangosaml2 will try to store the attribute in the User model if there is a matching field in that model. Otherwise it will try to do the same with your profile custom model. For multi-valued attributes only the first value is assigned to the destination field.

Alternatively, custom processing of attributes can be achieved by setting the value(s) in the SAML_ATTRIBUTE_MAPPING, to name(s) of method(s) defined on a custom django User object. In this case, each method is called by djangosaml2, passing the full list of attribute values extracted from the

<saml:attributevalue>
elements of the <saml:attribute>. Among other uses, this is a useful way to process
multi-valued attributes such as lists of user group names.</saml:attribute></saml:attributevalue>

For example::

Saml assertion snippet::

<saml:attribute name="groups" nameformat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:attributevalue>group1</saml:attributevalue>
        <saml:attributevalue>group2</saml:attributevalue>
        <saml:attributevalue>group3</saml:attributevalue></saml:attribute>

Custom User object::

from django.contrib.auth.models import AbstractUser

class User(AbstractUser):

```
def process_groups(self, groups):
  // process list of group names in argument 'groups'
  pass;
```

settings.py::

SAML_ATTRIBUTE_MAPPING = { 'groups': ('process_groups', ), }

Learn more about Django profile models at:

<https://docs.djangoproject.com/en/dev/topics/auth/#storing-additional-information-about-users>

Sometimes you need to use special logic to update the user object depending on the SAML2 attributes and the mapping described above is simply not enough. For these cases djangosaml2 provides a Django signal that you can listen to. In order to do so you can add the following code to your app::

from djangosaml2.signals import pre_user_save

def custom_update_user(sender=User, instance, attributes, user_modified, **kargs) ... return True # I modified the user object

Your handler will receive the user object, the list of SAML attributes and a flag telling you if the user is already modified and need to be saved after your handler is executed. If your handler modifies the user object it should return True. Otherwise it should return False. This way djangosaml2 will know if it should save the user object so you don't need to do it and no more calls to the save method are issued.

# IdP setup

Congratulations, you have finished configuring the SP side of the federation. Now you need to send the entity id and the metadata of this new SP to the IdP administrators so they can add it to their list of trusted services.

You can get this information starting your Django development server and going to the <http://localhost:8000/saml2/metadata> url. If you have included the djangosaml2 urls under a different url prefix you need to correct this url.

## SimpleSAMLphp issues

As of SimpleSAMLphp 1.8.2 there is a problem if you specify attributes in the SP configuration. When the SimpleSAMLphp metadata parser converts the XML into its custom php format it puts the following option::

'attributes.NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'

But it need to be replaced by this one::

'AttributeNameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'

Otherwise the Assertions sent from the IdP to the SP will have a wrong Attribute Name Format and pysaml2 will be confused.

Furthermore if you have a AttributeLimit filter in your SimpleSAMLphp configuration you will need to enable another attribute filter just before to make sure that the AttributeLimit does not remove the attributes from the authentication source. The filter you need to add is an AttributeMap filter like this::

10 => array( 'class' => 'core:AttributeMap', 'name2oid' ),

# Testing

One way to check if everything is working as expected is to enable the following url::

urlpatterns = patterns( '',

```
  #  lots of url definitions here

  (r'^saml2/', include('djangosaml2.urls')),
  (r'^test/', 'djangosaml2.views.echo_attributes'),

  #  more url definitions
```

)

Now if you go to the /test/ url you will see your SAML attributes and also a link to do a global logout.

You can also run the unit tests with the following command::

python tests/run_tests.py

If you have `tox`_ installed you can simply call tox inside the root directory and it will run the tests in multiple versions of Python.

.. _`tox`: <http://pypi.python.org/pypi/tox>

# FAQ

**Why can't SAML be implemented as an Django Authentication Backend?**

well SAML authentication is not that simple as a set of credentials you can put on a login form and get a response back. Actually the user password is not given to the service provider at all. This is by design. You have to delegate the task of authentication to the IdP and then get an asynchronous response from it.

Given said that, djangosaml2 does use a Django Authentication Backend to transform the SAML assertion about the user into a Django user object.

**Why not put everything in a Django middleware class and make our lifes easier?**

Yes, that was an option I did evaluate but at the end the current design won. In my opinion putting this logic into a middleware has the advantage of making it easier to configure but has a couple of disadvantages: first, the middleware would need to check if the request path is one of the SAML endpoints for every request. Second, it would be too magical and in case of a problem, much harder to debug.

**Why not call this package django-saml as many other Django applications?**

Following that pattern then I should import the application with import saml but unfortunately that module name is already used in pysaml2.
