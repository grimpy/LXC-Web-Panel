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

import lwp
import lxc
import lxclite
import subprocess
import time
import re
import hashlib
import sqlite3
import os

from flask import Flask, request, session, g, redirect, url_for, abort, \
    render_template, flash, jsonify

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

# configuration
config = configparser.SafeConfigParser()
config.readfp(open('lwp.conf'))

SECRET_KEY = '\xb13\xb6\xfb+Z\xe8\xd1n\x80\x9c\xe7KM' \
             '\x1c\xc1\xa7\xf8\xbeY\x9a\xfa<.'

DEBUG = config.getboolean('global', 'debug')
DATABASE = config.get('database', 'file')
ADDRESS = config.get('global', 'address')
PORT = int(config.get('global', 'port'))


# Flask app
app = Flask(__name__)
app.config.from_object(__name__)


def connect_db():
    '''
    SQLite3 connect function
    '''

    return sqlite3.connect(app.config['DATABASE'])


@app.before_request
def before_request():
    '''
    executes functions before all requests
    '''

    check_session_limit()
    g.db = connect_db()


@app.teardown_request
def teardown_request(exception):
    '''
    executes functions after all requests
    '''

    if hasattr(g, 'db'):
        g.db.close()


@app.route('/')
@app.route('/home')
def home():
    '''
    home page function
    '''
    if 'logged_in' in session:
        containers = lxc.list_containers(as_object=True)
        listx = {'RUNNING': [], 'FROZEN': [], 'STOPPED': []}
        for container in containers:
            listx[container.state].append(container)
        containers_all = []

        for status in ['RUNNING', 'FROZEN', 'STOPPED']:
            containers_by_status = []

            for container in listx[status]:
                ips = list()
                if status == 'RUNNING':
                    ips = container.get_ips()
                containers_by_status.append({
                    'name': container.name,
                    'ips': ips,
                    'memusg': lwp.memory_usage(container),
                    'settings': lwp.get_container_settings(container)
                })
            containers_all.append({
                'status': status.lower(),
                'containers': containers_by_status
            })

        return render_template('index.html', containers=lxc.list_containers(),
                               containers_all=containers_all,
                               dist=lwp.check_ubuntu(),
                               templates=lwp.get_templates_list())
    return render_template('login.html')


@app.route('/about')
def about():
    '''
    about page
    '''

    if 'logged_in' in session:
        return render_template('about.html', containers=lxc.list_containers(),
                               version=lwp.check_version())
    return render_template('login.html')


@app.route('/<name>/edit', methods=['POST', 'GET'])
def edit(name=None):
    '''
    edit containers page and actions if form post request
    '''

    if 'logged_in' in session:
        host_memory = lwp.host_memory_usage()
        container = lxc.Container(name)
        if request.method == 'POST':
            cfg = lwp.get_container_settings(container)
            ip_regex = '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]' \
                       '|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4]' \
                       '[0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]' \
                       '?[0-9][0-9]?)(/(3[0-2]|[12]?[0-9]))?'

            def get_int(data, key):
                value = data.get(key)
                if value and value.isdigit():
                    return int(value)
                return 0

            form = {}
            def parse_network():
                networks = list()
                for key, value in request.form.items():
                    if key.startswith('network'):
                        _, order, key = key.split('.')
                        order = int(order) 
                        if order + 1 > len(networks):
                            network = {'flags': 'down'}
                            networks.append(network)
                        else:
                            network = networks[order]
                        network[key] = value
                return networks

            networks = parse_network()

            form['rootfs'] = request.form['rootfs']
            form['utsname'] = request.form['hostname']
            form['memlimit'] = get_int(request.form, 'memlimit')
            form['swlimit'] = get_int(request.form, 'swlimit')
            form['cpus'] = get_int(request.form, 'cpus')
            form['shares'] = get_int(request.form, 'cpushares')
            try:
                form['autostart'] = request.form['autostart']
            except KeyError:
                form['autostart'] = False

            for idx, network in enumerate(networks):
                if network['flags'] == 'down':
                    container.network.remove(idx)
                    continue
                for prop in ('ipv4', 'type', 'link'):
                    cfgkey = 'lxc.network.%s.%s' % (idx, prop)
                    try:
                        value = container.get_config_item(cfgkey)
                    except KeyError:
                        value = ''
                    if network[prop] != value:
                        if network[prop]:
                            container.set_config_item(cfgkey, network[prop])
                        else:
                            container.clear_config_item(cfgkey)

            if form['utsname'] != cfg['utsname'] and \
                    re.match('(?!^containers$)|^(([a-zA-Z0-9]|[a-zA-Z0-9]'
                             '[a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|'
                             '[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$',
                             form['utsname']):
                container.set_config_item('lxc.utsname', form['utsname'])
                flash(u'Hostname updated for %s!' % container.name, 'success')

            if form['memlimit'] != cfg['memlimit'] and \
                    form['memlimit'] <= int(host_memory['total']):
                configkey = lwp.cgroup['memlimit']
                if form['memlimit'] >= int(host_memory['total'] - 10):
                    form['memlimit'] = 0

                if form['memlimit'] != cfg['memlimit']:
                    if form['memlimit'] == 0:
                        container.clear_config_item(configkey)
                    else:
                        container.set_config_item(configkey, str(form['memlimit']))
                    if container.state != 'STOPPED':
                        container.set_cgroup_item(configkey, str(form['memlimit']))
                    flash(u'Memory limit updated for %s!' % container.name,
                          'success')

            if form['swlimit'] != cfg['swlimit'] and \
                    form['swlimit'] <= int(host_memory['total'] * 2):

                configkey = lwp.cgroup['swlimit']
                if form['swlimit'] == int(host_memory['total'] * 2):
                    form['swlimit'] = 0

                if (form['memlimit'] == '' and form['swlimit'] != '') or \
                        (form['memlimit'] > form['swlimit'] and
                         form['swlimit'] != ''):
                    flash(u'Can\'t assign swap memory lower than'
                          ' the memory limit', 'warning')

                elif form['swlimit'] != cfg['swlimit'] and \
                        form['memlimit'] <= form['swlimit']:
                    container.set_config_item(configkey, str(form['swlimit']))

                    if container.state != 'STOPPED':
                        container.set_cgroup_item(configkey, str(form['swlimit']))
                    flash(u'Swap limit updated for %s!' % container.name, 'success')

            if (not form['cpus'] and form['cpus'] != cfg['cpus']) or \
                    (form['cpus'] != cfg['cpus'] and
                     re.match('^[0-9,-]+$', form['cpus'])):
                container.set_config_item('lxxc.cgroup.cpuset.cpus', str(form['cpus']))

                if container.state != 'STOPPED':
                    container.set_cgroup_item('lxc.cgroup.cpuset.cpus', str(form['cpus']))
                flash(u'CPUs updated for %s!' % container.name, 'success')

            if (not form['shares'] and form['shares'] != cfg['shares']) or \
                    (form['shares'] != cfg['shares'] and
                     re.match('^[0-9]+$', form['shares'])):
                container.set_config_item('lxc.cgroup.cpu.shares', str(form['shares']))
                if container.state != 'STOPPED':
                    container.set_cgroup_item('lxc.cgroup.cpu.shares', str(form['shares']))
                flash(u'CPU shares updated for %s!' % container.name, 'success')

            if form['rootfs'] != cfg['rootfs'] and \
                    re.match('^[a-zA-Z0-9_/\-\.]+', form['rootfs']):
                container.set_config_item('lxc.rootfs', form['rootfs'])
                flash(u'Rootfs updated!' % container.name, 'success')
            container.save_config()

            auto = lwp.ls_auto()
            if form['autostart'] == 'True' and \
                    not ('%s.conf' % container) in auto:
                try:
                    os.symlink('/var/lib/lxc/%s/config' % container,
                               '/etc/lxc/auto/%s.conf' % container)
                    flash(u'Autostart enabled for %s' % container, 'success')
                except OSError:
                    flash(u'Unable to create symlink \'/etc/lxc/auto/%s.conf\''
                          % container, 'error')
            elif not form['autostart'] and ('%s.conf' % container) in auto:
                try:
                    os.remove('/etc/lxc/auto/%s.conf' % container)
                    flash(u'Autostart disabled for %s' % container, 'success')
                except OSError:
                    flash(u'Unable to remove symlink', 'error')

        status = container.state
        pid = container.init_pid

        infos = {'status': status,
                 'pid': pid,
                 'memusg': lwp.memory_usage(container)}
        settings = lwp.get_container_settings(container)
        netstatus = 'up' in [ net['flags'] for net in settings['networks'] ]
        return render_template('edit.html', containers=lxc.list_containers(),
                               container=name, infos=infos,
                               settings=settings,
                               netstatus=netstatus,
                               host_memory=host_memory)
    return render_template('login.html')


@app.route('/settings/lxc-net', methods=['POST', 'GET'])
def lxc_net():
    '''
    lxc-net (/etc/default/lxc) settings page and actions if form post request
    '''
    if 'logged_in' in session:
        if session['su'] != 'Yes':
            return abort(403)

        if request.method == 'POST':
            if lxc.running() == []:
                cfg = lwp.get_net_settings()
                ip_regex = '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]' \
                           '|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4]' \
                           '[0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|' \
                           '[01]?[0-9][0-9]?)'

                form = {}
                try:
                    form['use'] = request.form['use']
                except KeyError:
                    form['use'] = 'false'

                try:
                    form['bridge'] = request.form['bridge']
                except KeyError:
                    form['bridge'] = None

                try:
                    form['address'] = request.form['address']
                except KeyError:
                    form['address'] = None

                try:
                    form['netmask'] = request.form['netmask']
                except KeyError:
                    form['netmask'] = None

                try:
                    form['network'] = request.form['network']
                except KeyError:
                    form['network'] = None

                try:
                    form['range'] = request.form['range']
                except KeyError:
                    form['range'] = None

                try:
                    form['max'] = request.form['max']
                except KeyError:
                    form['max'] = None

                if form['use'] == 'true' and form['use'] != cfg['use']:
                    lwp.push_net_value('USE_LXC_BRIDGE', 'true')

                elif form['use'] == 'false' and form['use'] != cfg['use']:
                    lwp.push_net_value('USE_LXC_BRIDGE', 'false')

                if form['bridge'] and form['bridge'] != cfg['bridge'] \
                        and re.match('^[a-zA-Z0-9_-]+$', form['bridge']):
                    lwp.push_net_value('LXC_BRIDGE', form['bridge'])

                if form['address'] and form['address'] != cfg['address'] \
                        and re.match('^%s$' % ip_regex, form['address']):
                    lwp.push_net_value('LXC_ADDR', form['address'])

                if form['netmask'] and form['netmask'] != cfg['netmask'] \
                        and re.match('^%s$' % ip_regex, form['netmask']):
                    lwp.push_net_value('LXC_NETMASK', form['netmask'])

                if form['network'] and form['network'] != cfg['network'] and \
                        re.match('^%s(?:/\d{1,2}|)$' % ip_regex,
                                 form['network']):
                    lwp.push_net_value('LXC_NETWORK', form['network'])

                if form['range'] and form['range'] != cfg['range'] and \
                        re.match('^%s,%s$' % (ip_regex, ip_regex),
                                 form['range']):
                    lwp.push_net_value('LXC_DHCP_RANGE', form['range'])

                if form['max'] and form['max'] != cfg['max'] and \
                        re.match('^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
                                 form['max']):
                    lwp.push_net_value('LXC_DHCP_MAX', form['max'])

                if lwp.net_restart() == 0:
                    flash(u'LXC Network settings applied successfully!',
                          'success')
                else:
                    flash(u'Failed to restart LXC networking.', 'error')
            else:
                flash(u'Stop all containers before restart lxc-net.',
                      'warning')
        return render_template('lxc-net.html', containers=lxc.list_containers(),
                               cfg=lwp.get_net_settings(),
                               running=lxc.list_containers(defined=False))
    return render_template('login.html')


@app.route('/lwp/users', methods=['POST', 'GET'])
def lwp_users():
    '''
    returns users and get posts request : can edit or add user in page.
    this funtction uses sqlite3
    '''
    if 'logged_in' in session:
        if session['su'] != 'Yes':
            return abort(403)

        try:
            trash = request.args.get('trash')
        except KeyError:
            trash = 0

        su_users = query_db("SELECT COUNT(id) as num FROM users "
                            "WHERE su='Yes'", [], one=True)

        if request.args.get('token') == session.get('token') and \
                int(trash) == 1 and request.args.get('userid') and \
                request.args.get('username'):
            nb_users = query_db("SELECT COUNT(id) as num FROM users", [],
                                one=True)

            if nb_users['num'] > 1:
                if su_users['num'] <= 1:
                    su_user = query_db("SELECT username FROM users "
                                       "WHERE su='Yes'", [], one=True)

                    if su_user['username'] == request.args.get('username'):
                        flash(u'Can\'t delete the last admin user : %s' %
                              request.args.get('username'), 'error')
                        return redirect(url_for('lwp_users'))

                g.db.execute("DELETE FROM users WHERE id=? AND username=?",
                             [request.args.get('userid'),
                              request.args.get('username')])
                g.db.commit()
                flash(u'Deleted %s' % request.args.get('username'), 'success')
                return redirect(url_for('lwp_users'))

            flash(u'Can\'t delete the last user!', 'error')
            return redirect(url_for('lwp_users'))

        if request.method == 'POST':
            users = query_db('SELECT id, name, username, su FROM users '
                             'ORDER BY id ASC')

            if request.form['newUser'] == 'True':
                if not request.form['username'] in \
                        [user['username'] for user in users]:
                    if re.match('^\w+$', request.form['username']) and \
                            request.form['password1']:
                        if request.form['password1'] == \
                                request.form['password2']:
                            if request.form['name']:
                                if re.match('[a-z A-Z0-9]{3,32}',
                                            request.form['name']):
                                    g.db.execute(
                                        "INSERT INTO users "
                                        "(name, username, password) "
                                        "VALUES (?, ?, ?)",
                                        [request.form['name'],
                                         request.form['username'],
                                         hash_passwd(
                                             request.form['password1'])])
                                    g.db.commit()
                                else:
                                    flash(u'Invalid name!', 'error')
                            else:
                                g.db.execute("INSERT INTO users "
                                             "(username, password) VALUES "
                                             "(?, ?)",
                                             [request.form['username'],
                                              hash_passwd(
                                                  request.form['password1'])])
                                g.db.commit()

                            flash(u'Created %s' % request.form['username'],
                                  'success')
                        else:
                            flash(u'No password match', 'error')
                    else:
                        flash(u'Invalid username or password!', 'error')
                else:
                    flash(u'Username already exist!', 'error')

            elif request.form['newUser'] == 'False':
                if request.form['password1'] == request.form['password2']:
                    if re.match('[a-z A-Z0-9]{3,32}', request.form['name']):
                        if su_users['num'] <= 1:
                            su = 'Yes'
                        else:
                            try:
                                su = request.form['su']
                            except KeyError:
                                su = 'No'

                        if not request.form['name']:
                            g.db.execute("UPDATE users SET name='', su=? "
                                         "WHERE username=?",
                                         [su, request.form['username']])
                            g.db.commit()
                        elif request.form['name'] and \
                                not request.form['password1'] and \
                                not request.form['password2']:
                            g.db.execute("UPDATE users SET name=?, su=? "
                                         "WHERE username=?",
                                         [request.form['name'], su,
                                          request.form['username']])
                            g.db.commit()
                        elif request.form['name'] and \
                                request.form['password1'] and \
                                request.form['password2']:
                            g.db.execute("UPDATE users SET "
                                         "name=?, password=?, su=? WHERE "
                                         "username=?",
                                         [request.form['name'],
                                          hash_passwd(
                                              request.form['password1']),
                                          su, request.form['username']])
                            g.db.commit()
                        elif request.form['password1'] and \
                                request.form['password2']:
                            g.db.execute("UPDATE users SET password=?, su=? "
                                         "WHERE username=?",
                                         [hash_passwd(
                                             request.form['password1']),
                                          su, request.form['username']])
                            g.db.commit()

                        flash(u'Updated', 'success')
                    else:
                        flash(u'Invalid name!', 'error')
                else:
                    flash(u'No password match', 'error')
            else:
                flash(u'Unknown error!', 'error')

        users = query_db("SELECT id, name, username, su FROM users "
                         "ORDER BY id ASC")
        nb_users = query_db("SELECT COUNT(id) as num FROM users", [], one=True)
        su_users = query_db("SELECT COUNT(id) as num FROM users "
                            "WHERE su='Yes'", [], one=True)

        return render_template('users.html', containers=lxc.list_containers(), users=users,
                               nb_users=nb_users, su_users=su_users)
    return render_template('login.html')


@app.route('/checkconfig')
def checkconfig():
    '''
    returns the display of lxc-checkconfig command
    '''
    if 'logged_in' in session:
        if session['su'] != 'Yes':
            return abort(403)

        return render_template('checkconfig.html', containers=lxc.list_containers(),
                               cfg=lxclite.checkconfig())
    return render_template('login.html')


@app.route('/action', methods=['GET'])
def action():
    '''
    manage all actions related to containers
    lxc-start, lxc-stop, etc...
    '''
    if 'logged_in' in session:
        if request.args['token'] == session.get('token'):
            action = request.args['action']
            name = request.args['name']
            container = lxc.Container(name)

            if action == 'start':
                if container.start():
                    # Fix bug : "the container is randomly not
                    #            displayed in overview list after a boot"
                    time.sleep(1)
                    flash(u'Container %s started successfully!' % name,
                          'success')
                else:
                    flash(u'Unable to start %s!' % name, 'error')
            elif action == 'stop':
                if container.stop():
                    flash(u'Container %s stopped successfully!' % name,
                          'success')
                else:
                    flash(u'Unable to stop %s!' % name, 'error')
            elif action == 'freeze':
                if container.freeze():
                    flash(u'Container %s frozen successfully!' % name,
                          'success')
                else:
                    flash(u'Unable to freeze %s!' % name, 'error')
            elif action == 'unfreeze':
                if container.unfreeze():
                    flash(u'Container %s unfrozen successfully!' % name,
                          'success')
                else:
                    flash(u'Unable to unfeeze %s!' % name, 'error')
            elif action == 'destroy':
                if session['su'] != 'Yes':
                    return abort(403)
                try:
                    if container.destroy():
                        flash(u'Container %s destroyed successfully!' % name,
                              'success')
                    else:
                        flash(u'Unable to destroy %s!' % name, 'error')
                except lxc.ContainerDoesntExists:
                    flash(u'The Container %s does not exists!' % name, 'error')
            elif action == 'reboot' and name == 'host':
                if session['su'] != 'Yes':
                    return abort(403)
                msg = '\v*** LXC Web Panel *** \
                        \nReboot from web panel'
                try:
                    subprocess.check_call('/sbin/shutdown -r now \'%s\'' % msg,
                                          shell=True)
                    flash(u'System will now restart!', 'success')
                except:
                    flash(u'System error!', 'error')
        try:
            if request.args['from'] == 'edit':
                return redirect('../%s/edit' % name)
            else:
                return redirect(url_for('home'))
        except:
            return redirect(url_for('home'))
    return render_template('login.html')


@app.route('/action/create-container', methods=['GET', 'POST'])
def create_container():
    '''
    verify all forms to create a container
    '''
    if 'logged_in' in session:
        if session['su'] != 'Yes':
            return abort(403)
        if request.method == 'POST':
            name = request.form['name']
            template = request.form['template']
            command = request.form['command']

            if re.match('^(?!^containers$)|[a-zA-Z0-9_-]+$', name):
                storage_method = request.form['backingstore']

                if storage_method == 'default':
                    try:
                        if lxc.create(name, template=template,
                                      xargs=command) == 0:
                            flash(u'Container %s created successfully!' % name,
                                  'success')
                        else:
                            flash(u'Failed to create %s!' % name, 'error')
                    except lxc.ContainerAlreadyExists:
                        flash(u'The Container %s is already created!' % name,
                              'error')
                    except subprocess.CalledProcessError:
                        flash(u'Error!' % name, 'error')

                elif storage_method == 'directory':
                    directory = request.form['dir']

                    if re.match('^/[a-zA-Z0-9_/-]+$', directory) and \
                            directory != '':
                        try:
                            if lxc.create(name, template=template,
                                          storage='dir --dir %s' % directory,
                                          xargs=command) == 0:
                                flash(u'Container %s created successfully!'
                                      % name, 'success')
                            else:
                                flash(u'Failed to create %s!' % name, 'error')
                        except lxc.ContainerAlreadyExists:
                            flash(u'The Container %s is already created!'
                                  % name, 'error')
                        except subprocess.CalledProcessError:
                            flash(u'Error!' % name, 'error')

                elif storage_method == 'lvm':
                    lvname = request.form['lvname']
                    vgname = request.form['vgname']
                    fstype = request.form['fstype']
                    fssize = request.form['fssize']
                    storage_options = 'lvm'

                    if re.match('^[a-zA-Z0-9_-]+$', lvname) and lvname != '':
                        storage_options += ' --lvname %s' % lvname
                    if re.match('^[a-zA-Z0-9_-]+$', vgname) and vgname != '':
                        storage_options += ' --vgname %s' % vgname
                    if re.match('^[a-z0-9]+$', fstype) and fstype != '':
                        storage_options += ' --fstype %s' % fstype
                    if re.match('^[0-9][G|M]$', fssize) and fssize != '':
                        storage_options += ' --fssize %s' % fssize

                    try:
                        if lxc.create(name, template=template,
                                      storage=storage_options,
                                      xargs=command) == 0:
                            flash(u'Container %s created successfully!' % name,
                                  'success')
                        else:
                            flash(u'Failed to create %s!' % name, 'error')
                    except lxc.ContainerAlreadyExists:
                        flash(u'The container/logical volume %s is '
                              'already created!' % name, 'error')
                    except subprocess.CalledProcessError:
                        flash(u'Error!' % name, 'error')

                else:
                    flash(u'Missing parameters to create container!', 'error')

            else:
                if name == '':
                    flash(u'Please enter a container name!', 'error')
                else:
                    flash(u'Invalid name for \"%s\"!' % name, 'error')

        return redirect(url_for('home'))
    return render_template('login.html')


@app.route('/action/clone-container', methods=['GET', 'POST'])
def clone_container():
    '''
    verify all forms to clone a container
    '''
    if 'logged_in' in session:
        if session['su'] != 'Yes':
            return abort(403)
        if request.method == 'POST':
            orig = request.form['orig']
            name = request.form['name']

            try:
                snapshot = request.form['snapshot']
                if snapshot == 'True':
                    snapshot = True
            except KeyError:
                snapshot = False

            if re.match('^(?!^containers$)|[a-zA-Z0-9_-]+$', name):
                container = lxc.Container(orig)
                flags = 0 if not snapshot else lxc.LXC_CLONE_SNAPSHOT
                if not container.clone(name, flags=flags):
                    flash(u'Failed to clone %s into %s!' % (orig, name),
                          'error')
                else:
                    flash(u'Container %s cloned into %s successfully!'
                          % (orig, name), 'success')
            else:
                if name == '':
                    flash(u'Please enter a container name!', 'error')
                else:
                    flash(u'Invalid name for \"%s\"!' % name, 'error')

        return redirect(url_for('home'))
    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        request_username = request.form['username']
        request_passwd = hash_passwd(request.form['password'])

        current_url = request.form['url']

        user = query_db('select name, username, su from users where username=?'
                        'and password=?', [request_username, request_passwd],
                        one=True)

        if user:
            session['logged_in'] = True
            session['token'] = get_token()
            session['last_activity'] = int(time.time())
            session['username'] = user['username']
            session['name'] = user['name']
            session['su'] = user['su']
            flash(u'You are logged in!', 'success')

            if current_url == url_for('login'):
                return redirect(url_for('home'))
            return redirect(current_url)

        flash(u'Invalid username or password!', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('token', None)
    session.pop('last_activity', None)
    session.pop('username', None)
    session.pop('name', None)
    session.pop('su', None)
    flash(u'You are logged out!', 'success')
    return redirect(url_for('login'))


@app.route('/_refresh_cpu_host')
def refresh_cpu_host():
    if 'logged_in' in session:
        return lwp.host_cpu_percent()


@app.route('/_refresh_uptime_host')
def refresh_uptime_host():
    if 'logged_in' in session:
        return jsonify(lwp.host_uptime())


@app.route('/_refresh_disk_host')
def refresh_disk_host():
    if 'logged_in' in session:
        return jsonify(lwp.host_disk_usage(partition=config.get('overview',
                                                                'partition')))


@app.route('/_refresh_memory_<name>')
def refresh_memory_containers(name=None):
    if 'logged_in' in session:
        if name == 'containers':
            containers_running = lxc.list_containers(active=True, defined=False, as_object=True)
            containers = []
            for container in containers_running:
                name = container.name.replace(' (auto)', '')
                containers.append({'name': name,
                                   'memusg': lwp.memory_usage(container)})
            return jsonify(data=containers)
        elif name == 'host':
            return jsonify(lwp.host_memory_usage())
        return jsonify({'memusg': lwp.memory_usage(lxc.Container(name))})


@app.route('/_check_version')
def check_version():
    if 'logged_in' in session:
        return jsonify(lwp.check_version())


def hash_passwd(passwd):
    return hashlib.sha512(passwd.encode()).hexdigest()


def get_token():
    return hashlib.md5(str(time.time()).encode()).hexdigest()


def query_db(query, args=(), one=False):
    cur = g.db.execute(query, args)
    rv = [dict((cur.description[idx][0], value)
          for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv


def check_session_limit():
    if 'logged_in' in session and session.get('last_activity') is not None:
        now = int(time.time())
        limit = now - 60 * int(config.get('session', 'time'))
        last_activity = session.get('last_activity')
        if last_activity < limit:
            flash(u'Session timed out !', 'info')
            logout()
        else:
            session['last_activity'] = now

if __name__ == '__main__':
    app.run(host=app.config['ADDRESS'], port=app.config['PORT'])
