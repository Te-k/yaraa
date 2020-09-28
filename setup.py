from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='yaraa',
    version='0.1.1',
    description='Advanced Yara tool',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Te-k/yaraa',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='archive',
    install_requires=['yara-python==3.11.0', 'androguard==3.3.5', 'python-magic==0.4.15', 'oletools', 'pyyaml'],
    license='MIT',
    python_requires='>=3.5',
    packages=['yaraa'],
    entry_points= {
        'console_scripts': [ 'yaraa=yaraa.cli:main', 'yaraa-config=yaraa.cli:config' ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]

)
