"""Python setup script for bluepy"""

import subprocess
import shlex
import sys
import os
from setuptools.command.build_py import build_py
from setuptools import setup

VERSION = '1.3.0'


def pre_install():
    """Do the custom compiling of the bluepy-helper executable from the
       Makefile
    """
    try:
        cwd = os.getcwd()
        print(f'Working dir is {cwd}')
        with open('bluepy/version.h', 'w') as verfile:
            verfile.write(f'#define VERSION_STRING "{VERSION}"\n')
        for cmd in ['make -C ./bluepy clean', 'make -C bluepy -j1']:
            print(f'execute {cmd}')
            subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as error:
        print('Failed to compile bluepy-helper. Exiting install.')
        print(f'Command was {cmd} in {cwd}')
        print(f'Return code was {error.returncode}')
        print(f'Output was:\n{error.output}')
        sys.exit(1)


class BluePyBuildPy(build_py):
    def run(self):
        pre_install()
        super().run()


setup_cmdclass = {
    'build_py': BluePyBuildPy,
}

# Force package to be *not* pure Python
# Discusssed at issue #158

try:
    from wheel.bdist_wheel import bdist_wheel

    class BluepyBdistWheel(bdist_wheel):
        def finalize_options(self):
            bdist_wheel.finalize_options(self)
            self.root_is_pure = False

    setup_cmdclass['bdist_wheel'] = BluepyBdistWheel
except ImportError:
    pass


setup(
    name='bluepy',
    version=VERSION,
    description='Python module for interfacing with BLE devices through Bluez',
    author='Ian Harvey',
    author_email='website-contact@fenditton.org',
    url='https://github.com/IanHarvey/bluepy',
    download_url=f'https://github.com/IanHarvey/bluepy/tarball/v/{VERSION}',
    keywords=['Bluetooth', 'Bluetooth Smart', 'BLE', 'Bluetooth Low Energy'],
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],
    packages=['bluepy'],

    package_data={
        'bluepy': ['bluepy-helper', '*.json', 'bluez-src.tgz', 'bluepy-helper.c', 'version.h', 'Makefile']
    },
    cmdclass=setup_cmdclass,
    entry_points={
        'console_scripts': [
            'thingy52=bluepy.thingy52:main',
            'sensortag=bluepy.sensortag:main',
            'blescan=bluepy.blescan:main',
        ]
    }
)
