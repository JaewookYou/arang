from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name                = 'arang',
    version             = '0.62',
    description         = 'my own module for webhacking using python3',
    long_description	= long_description,
    long_description_content_type	= "text/markdown",
    author              = 'arang',
    author_email        = 'jwyou@fsec.or.kr',
    url                 = 'https://github.com/JaewookYou/arang',
    packages            = find_packages(exclude = []),
    keywords            = ['arang'],
    python_requires     = '>=3',
    package_data        = {},
    zip_safe            = False,
    classifiers         = [
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.1',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
)
