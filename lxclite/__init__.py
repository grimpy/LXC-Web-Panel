# LXC Python Library
# for compatibility with LXC 0.8 and 0.9
# on Ubuntu 12.04/12.10/13.04

# Author: Elie Deloumeau
# Contact: elie@deloumeau.fr

# The MIT License (MIT)
# Copyright (c) 2013 Elie Deloumeau

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import subprocess


def _run(cmd, output=False):
    '''
    To run command easier
    '''

    if output:
        try:
            out = subprocess.check_output('{}'.format(cmd), shell=True,
                                          universal_newlines=True)
        except subprocess.CalledProcessError:
            out = False

        return out

    return subprocess.check_call('{}'.format(cmd), shell=True,
                                 universal_newlines=True)  # returns 0 for True


def create(container, template='ubuntu', storage=None, xargs=None):
    '''
    Create a container (without all options)
    Default template: Ubuntu
    '''

    if exists(container):
        raise ContainerAlreadyExists(
            'Container {} already created!'.format(container))

    command = 'lxc-create -n {}'.format(container)
    command += ' -t {}'.format(template)

    if storage:
        command += ' -B {}'.format(storage)

    if xargs:
        command += ' -- {}'.format(xargs)

    return _run(command)


def checkconfig():
    '''
    Returns the output of lxc-checkconfig (colors cleared)
    '''

    out = _run('lxc-checkconfig', output=True)

    if out:
        return out.replace('[1;32m', '').replace('[1;33m', '') \
            .replace('[0;39m', '').replace('[1;32m', '') \
            .replace('\x1b', '').replace(': ', ':').split('\n')

    return out


def cgroup(container, key, value):
    if not exists(container):
        raise ContainerDoesntExists(
            'Container {} does not exist!'.format(container))

    return _run('lxc-cgroup -n {} {} {}'.format(container, key, value))
