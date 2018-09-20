from setuptools import setup, find_packages

setup(
    name='keycloakauthenticator',
    version='0.8.0',
    install_requires=[
        'oauthenticator',
        'python-jose'
    ],
    description='A small extension of oauthenticator to better integrate with KeyCloak.',
    url='http://github.com/ausecocloud/keycloakauthenticator',
    author='Gerhard Weis',
    author_email='g.weis@griffith.edu.au',
    license='BSD',
    packages=['keycloakauthenticator'],
)
