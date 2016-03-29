import sys
import json
import subprocess
import collections
from fnmatch import fnmatch as matches
import os
import selinux
from .client import get_docker_client
from yaml import load as yaml_load

"""Atomic Utility Module"""

ReturnTuple = collections.namedtuple('ReturnTuple',
                                     ['return_code', 'stdout', 'stderr'])

if sys.version_info[0] < 3:
    input = raw_input
else:
    input = input


def _decompose(compound_name):
    """ '[reg/]repo[:tag]' -> (reg, repo, tag) """
    reg, repo, tag = '', compound_name, ''
    if '/' in repo:
        reg, repo = repo.split('/', 1)
    if ':' in repo:
        repo, tag = repo.rsplit(':', 1)
    return reg, repo, tag

def image_by_name(img_name, images=None):
    """
    Returns a list of image data for images which match img_name. Will
    optionally take a list of images from a docker.Client.images
    query to avoid multiple docker queries.
    """
    i_reg, i_rep, i_tag = _decompose(img_name)

    # Correct for bash-style matching expressions.
    if not i_reg:
        i_reg = '*'
    if not i_tag:
        i_tag = '*'

    # If the images were not passed in, go get them.
    if images is None:
        c = get_docker_client()
        images = c.images(all=False)

    valid_images = []
    for i in images:
        for t in i['RepoTags']:
            reg, rep, tag = _decompose(t)
            if matches(reg, i_reg) \
                    and matches(rep, i_rep) \
                    and matches(tag, i_tag):
                valid_images.append(i)
                break
            # Some repo after decompose end up with the img_name
            # at the end.  i.e. rhel7/rsyslog
            if rep.endswith(img_name):
                valid_images.append(i)
                break
    return valid_images


def subp(cmd):
    """
    Run a command as a subprocess.
    Return a triple of return code, standard out, standard err.
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out, err = proc.communicate()
    return ReturnTuple(proc.returncode, stdout=out, stderr=err)


def check_call(cmd, env=os.environ, stderr=None, stdout=None):
    # Make sure cmd is a list
    if not isinstance(cmd, list):
        cmd = cmd.split(" ")
    return subprocess.check_call(cmd, env=env, stderr=stderr, stdout=stdout)

def default_container_context():
    if selinux.is_selinux_enabled() != 0:
        fd = open(selinux.selinux_lxc_contexts_path())
        for i in fd.readlines():
            name, context = i.split("=")
            if name.strip() == "file":
                return context.strip("\n\" ")
    return ""


def writeOut(output, lf="\n"):
    sys.stdout.flush()
    sys.stdout.write(str(output) + lf)


def output_json(json_data):
    ''' Pretty print json data '''
    writeOut(json.dumps(json_data, indent=4, separators=(',', ': ')))


def get_mounts_by_path():
    '''
    Gets all mounted devices and paths
    :return: dict of mounted devices and related information by path
    '''
    mount_info = []
    f = open('/proc/mounts', 'r')
    for line in f:
        _tmp = line.split(" ")
        mount_info.append({'path': _tmp[1],
                           'device': _tmp[0],
                           'type': _tmp[2],
                           'options': _tmp[3]
                           }
                          )
    return mount_info


def is_dock_obj_mounted(docker_obj):
    '''
    Check if the provided docker object, which needs to be an ID,
    is currently mounted and should be considered "busy"
    :param docker_obj: str, must be in ID format
    :return: bool True or False
    '''
    mount_info = get_mounts_by_path()
    devices = [x['device'] for x in mount_info]
    # If we can find the ID of the object in the list
    # of devices which comes from mount, safe to assume
    # it is busy.
    return any(docker_obj in x for x in devices)


def urllib3_disable_warnings():
    if not 'requests' in sys.modules:
        import requests
    else:
        requests = sys.modules['requests']

    # On latest Fedora, this is a symlink
    if hasattr(requests, 'packages'):
        requests.packages.urllib3.disable_warnings() #pylint: disable=maybe-no-member
    else:
        # But with python-requests-2.4.3-1.el7.noarch, we need
        # to talk to urllib3 directly
        have_urllib3 = False
        try:
            if not 'urllib3' in sys.modules:
                import urllib3
                have_urllib3 = True
        except ImportError as e:
            pass
        if have_urllib3:
            # Except only call disable-warnings if it exists
            if hasattr(urllib3, 'disable_warnings'):
                urllib3.disable_warnings()


def skopeo(image):
    """
    Performs remote inspection of an image on a registry
    :param image:  fully qualified name
    :return: Returns json formatted data
    """

    cmd = ['/usr/bin/skopeo', image]
    results = subp(cmd)
    if results.return_code is not 0:
        raise ValueError(results.stderr)
    else:
        return json.loads(results.stdout.decode('utf-8'))


class NoDockerDaemon(Exception):
    def __init__(self):
        Exception.__init__(self, "The docker daemon does not appear to be running.")


class DockerObjectNotFound(ValueError):
    def __init__(self, msg):
        Exception.__init__(self, "Unable to associate '{}' with an image or container".format(msg))


def get_atomic_config():
    """
    Returns the atomic configuration file (/etc/atomic.conf)
    in a dict
    :return: dict based structure of the atomic config file
    """
    atomic_conf = '/etc/atomic.conf'
    if not os.path.exists(atomic_conf):
        raise ValueError("{} does not exist".format(atomic_conf))
    with open(atomic_conf, 'r') as conf_file:
        return yaml_load(conf_file)
