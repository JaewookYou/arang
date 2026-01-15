from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='arang',
    version='2.0.0',
    description='Python module for web hacking and security testing',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='arang',
    author_email='jwyou@fsec.or.kr',
    url='https://github.com/JaewookYou/arang',
    packages=find_packages(exclude=['test', 'test.*']),
    keywords=['arang', 'webhacking', 'security', 'ctf', 'crypto'],
    python_requires='>=3.8',
    install_requires=[
        'requests>=2.25.0',
        'pycryptodome>=3.15.0',
        'pyperclip>=1.8.0',
    ],
    extras_require={
        'seed': ['kisa-seed>=1.0.0'],  # Optional SEED crypto package
    },
    package_data={},
    zip_safe=False,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Operating System :: OS Independent',
    ],
)
