from setuptools import find_packages, setup

import os


def read(*rnames):
    return open(os.path.join(os.path.dirname(__file__), *rnames)).read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='penndjangosaml2',
    version='0.16.1',
    description='Penn version of pysaml2 integration for Django',
    long_description='\n\n'.join([read('README.md'), read('CHANGES')]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Framework :: Django :: 1.7",
        "Framework :: Django :: 1.8",
        "Framework :: Django :: 1.9",
        "Framework :: Django :: 1.10",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        ],
    keywords="django,pysaml2,sso,saml2,federated authentication,authentication",
    author="Yaco Sistemas and independent contributors",
    author_email="sturoscy@wharton.upenn.edu",
    maintainer="Stephen Turoscy",
    url="https://github.com/wharton/penndjangosaml2",
    license='Apache 2.0',
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'defusedxml==0.4.1',
        'django-braces==1.11.0',
        'django-environ==0.4.0',
        'pysaml2>=4.5,<4.6',
        'requests>=2.20',
    ],
)
