from setuptools import setup, find_packages

long_description = 'gui for fwlite-cli'

setup(
    name="fwlite-gui",
    version="0.0.2",
    license='GPLv3',
    description="gui for fwlite-cli",
    author='v3aqb',
    author_email='null',
    url='https://github.com/v3aqb/fwlite-gui',
    packages=find_packages(),
    package_data={
        'fwlite-gui': ['README.rst', 'LICENSE']
    },
    entry_points={
        'gui_scripts': [
            'fwlite-gui = fwlite_gui.__main__:main'
        ]
    },
    include_package_data=True,
    dependency_links=['https://github.com/v3aqb/hxcrypto/archive/master.zip#egg=hxcrypto-0.0.3',
                      'https://github.com/v3aqb/fwlite-cli/archive/master.zip#egg=fwlite-cli-0.2',
                      ],
    install_requires=["hxcrypto", "fwlite-cli >= 0.2", "pyqt5", "chardet", "dnslib"],
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: Proxy Servers',
    ],
    long_description=long_description,
)
