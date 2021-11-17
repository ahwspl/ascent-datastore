from glob import glob
from setuptools import setup, find_packages

VERSION = "1.0.0"

setup(
    name='ascent-datastore-client',
    version=VERSION,
    description='Ascent Datastore Client Package',
    author='Darshit Kothari',
    author_email='darshit.kothari@ahwspl.com',
    packages=find_packages(),
    url='https://github.com/darshitkothari/ascent-datastore.git',
    install_requires=[
        'pyyaml~=5.0',
        'elasticsearch==7.10.0',
        'requests==2.24.0',
        'coloredlogs'
    ],
    include_package_data=True,
    package_data={
        'ascent.datastore': ['config/*.cfg']
    }
    
 )
