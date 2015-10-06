import sys
import os
import argparse
import docker
import json
import subprocess
import getpass
import requests
import pipes
import pwd
import time
import math
import Atomic.mount as mount
import Atomic.util as util
import Atomic.satellite as satellite
import Atomic.pulp as pulp
import dbus
from datetime import datetime

try:
    from subprocess import DEVNULL  # pylint: disable=no-name-in-module
except ImportError:
    DEVNULL = open(os.devnull, 'wb')

IMAGES = []


def convert_size(size):
    if size > 0:
        size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        i = int(math.floor(math.log(size, 1000)))
        p = math.pow(1000, i)
        s = round(size/p, 2)
        if s > 0:
            return '%s %s' % (s, size_name[i])
    return '0B'


def find_repo_tag(d, id):
    global IMAGES
    if len(IMAGES) == 0:
        IMAGES = d.images()
    for image in IMAGES:
        if id == image["Id"]:
            return image["RepoTags"][0]
    return ""


class Atomic(object):
    INSTALL_ARGS = ["/usr/bin/docker", "run",
                    "-t",
                    "-i",
                    "--rm",
                    "--privileged",
                    "-v", "/:/host",
                    "--net=host",
                    "--ipc=host",
                    "--pid=host",
                    "-e", "HOST=/host",
                    "-e", "NAME=${NAME}",
                    "-e", "IMAGE=${IMAGE}",
                    "-e", "CONFDIR=/host/etc/${NAME}",
                    "-e", "LOGDIR=/host/var/log/${NAME}",
                    "-e", "DATADIR=/host/var/lib/${NAME}",
                    "--name", "${NAME}",
                    "${IMAGE}"]

    SPC_ARGS = ["/usr/bin/docker", "run",
                "-t",
                "-i",
                "--rm",
                "--privileged",
                "-v", "/:/host",
                "-v", "/run:/run",
                "-v", "/etc/localtime:/etc/localtime",
                "--net=host",
                "--ipc=host",
                "--pid=host",
                "-e", "HOST=/host",
                "-e", "NAME=${NAME}",
                "-e", "IMAGE=${IMAGE}",
                "${IMAGE}"]

    RUN_ARGS = ["/usr/bin/docker", "create",
                "-t",
                "-i",
                "--name", "${NAME}",
                "${IMAGE}"]

    INSTALL_FILE = "/etc/atomic.d/install"

    def __init__(self):
        self.d = docker.Client()
        self.name = None
        self.image = None
        self.spc = False
        self.inspect = None
        self.force = False
        self._images = []
        self.containers = False
        self.images_cache = None

    def writeOut(self, output, lf="\n"):
        sys.stdout.flush()
        sys.stdout.write(output + lf)

    def get_label(self, label, image=None):
        inspect = self._inspect_image(image)
        cfg = inspect.get("Config", None)
        if cfg:
            labels = cfg.get("Labels", [])
            if labels and label in labels:
                return labels[label]
        return ""

    def force_delete_containers(self):
        if self._inspect_image():
            image = self.image
            if self.image.find(":") == -1:
                image += ":latest"
            for c in self.get_containers():
                if c["Image"] == image:
                    self.d.remove_container(c["Id"], force=True)

    def update(self):
        if self.force:
            self.force_delete_containers()
        return subprocess.check_call(["/usr/bin/docker", "pull", self.image])

    def pull(self):
        prevstatus = ""
        for line in self.d.pull(self.image, stream=True):
            bar = json.loads(line)
            status = bar['status']
            if prevstatus != status:
                self.writeOut(status, "")
            if 'id' not in bar:
                continue
            if status == "Downloading":
                self.writeOut(bar['progress'] + " ")
            elif status == "Extracting":
                self.writeOut("Extracting: " + bar['id'])
            elif status == "Pull complete":
                pass
            elif status.startswith("Pulling"):
                self.writeOut("Pulling: " + bar['id'])

            prevstatus = status
        self.writeOut("")

    def push(self):
        prevstatus = ""
        # Priority order:
        # If user passes in a password/username/url/ssl flag, use that
        # If not, read from the config file
        # If still nothing, ask again for registry user/pass
        if self.args.pulp:
            config = pulp.PulpConfig().config()

        if self.args.satellite:
            config = satellite.SatelliteConfig().config()

        if (self.args.satellite | self.args.pulp):
            if not self.args.username:
                self.args.username = config["username"]
            if not self.args.password:
                self.args.password = config["password"]
            if not self.args.url:
                self.args.url = config["url"]
            if self.args.verify_ssl is None:
                self.args.verify_ssl = config["verify_ssl"]

        if self.args.verify_ssl is None:
            self.args.verify_ssl = False

        if not self.args.username:
            self.args.username = util.input("Registry Username: ")

        if not self.args.password:
            self.args.password = getpass.getpass("Registry Password: ")

        if (self.args.satellite | self.args.pulp):
            if not self.args.url:
                self.args.url = util.input("URL: ")

        if self.args.pulp:
                    return pulp.push_image_to_pulp(self.image, self.args.url,
                                                   self.args.username,
                                                   self.args.password,
                                                   self.args.verify_ssl,
                                                   self.d)

        if self.args.satellite:
            if not self.args.activation_key:
                self.args.activation_key = util.input("Activation Key: ")
            if not self.args.repo_id:
                self.args.repo_id = util.input("Repository ID: ")
            return satellite.push_image_to_satellite(self.image,
                                                     self.args.url,
                                                     self.args.username,
                                                     self.args.password,
                                                     self.args.verify_ssl,
                                                     self.d,
                                                     self.args.activation_key,
                                                     self.args.repo_id,
                                                     self.args.debug)

        else:
            self.d.login(self.args.username, self.args.password)
            for line in self.d.push(self.image, stream=True):
                bar = json.loads(line)
                status = bar['status']
                if prevstatus != status:
                    self.writeOut(status, "")
                if 'id' not in bar:
                    continue
                if status == "Uploading":
                    self.writeOut(bar['progress'] + " ")
                elif status == "Push complete":
                    pass
                elif status.startswith("Pushing"):
                    self.writeOut("Pushing: " + bar['id'])

                prevstatus = status

    def set_args(self, args):
        self.args = args
        try:
            self.image = args.image
        except:
            pass
        try:
            self.command = args.command
        except:
            self.command = None

        try:
            self.spc = args.spc
        except:
            self.spc = False

        try:
            self.name = args.name
        except:
            pass

        try:
            self.force = args.force
        except:
            pass

        if not self.name and self.image is not None:
            self.name = self.image.split("/")[-1].split(":")[0]
            if self.spc:
                self.name = self.name + "-spc"

    def _getconfig(self, key, default=None):
        assert self.inspect is not None
        cfg = self.inspect.get("Config")
        if cfg is None:
            return default
        val = cfg.get(key, default)
        if val is None:
            return default
        return val

    def _get_cmd(self):
        return self._getconfig("Cmd", ["/bin/sh"])

    def _get_labels(self):
        return self._getconfig("Labels", [])

    def _interactive(self):
        return (self._getconfig("AttachStdin", False) and
                self._getconfig("AttachStdout", False) and
                self._getconfig("AttachStderr", False))

    def _running(self):
        if self._interactive():
            cmd = ["/usr/bin/docker", "exec", "-t", "-i", self.name]
            if self.command:
                cmd += self.command
            else:
                cmd += self._get_cmd()
            if self.args.display:
                return self.display(cmd)
            else:
                return subprocess.check_call(cmd, stderr=DEVNULL)
        else:
            if self.command:
                if self.args.display:
                    return self.writeOut("/usr/bin/docker exec -t -i %s %s" %
                                         (self.name, self.command))
                else:
                    return subprocess.check_call(
                        ["/usr/bin/docker", "exec", "-t", "-i", self.name] +
                        self.command, stderr=DEVNULL)
            else:
                if not self.args.display:
                    self.writeOut("Container is running")

    def _start(self):
        if self._interactive():
            if self.command:
                subprocess.check_call(
                    ["/usr/bin/docker", "start", self.name],
                    stderr=DEVNULL)
                return subprocess.check_call(
                    ["/usr/bin/docker", "exec", "-t", "-i", self.name] +
                    self.command)
            else:
                return subprocess.check_call(
                    ["/usr/bin/docker", "start", "-i", "-a", self.name],
                    stderr=DEVNULL)
        else:
            if self.command:
                subprocess.check_call(
                    ["/usr/bin/docker", "start", self.name],
                    stderr=DEVNULL)
                return subprocess.check_call(
                    ["/usr/bin/docker", "exec", "-t", "-i", self.name] +
                    self.command)
            else:
                return subprocess.check_call(
                    ["/usr/bin/docker", "start", self.name],
                    stderr=DEVNULL)

    def _inspect_image(self, image=None):
        try:
            if image:
                return self.d.inspect_image(image)
            return self.d.inspect_image(self.image)
        except docker.errors.APIError:
            pass
        except requests.exceptions.ConnectionError as e:
            raise IOError("Unable to communicate with docker daemon: %s\n" %
                          str(e))
        return None

    def _inspect_container(self):
        try:
            return self.d.inspect_container(self.name)
        except docker.errors.APIError:
            pass
        except requests.exceptions.ConnectionError as e:
            raise IOError("Unable to communicate with docker daemon: %s\n" %
                          str(e))
        return None

    def _get_args(self, label):
        labels = self._get_labels()
        for l in [label, label.lower(), label.capitalize(), label.upper()]:
            if l in labels:
                return labels[l].split()
        return None

    def _check_latest(self):
        inspect = self._inspect_image()
        if inspect and inspect["Id"] != self.inspect["Image"]:
            sys.stdout.write(
                "The '%(name)s' container is using an older version of the "
                "installed\n'%(image)s' container image. If you wish to use "
                "the newer image,\nyou must either create a new container "
                "with a new name or\nuninstall the '%(name)s' container."
                "\n\n# atomic uninstall --name %(name)s %(image)s\n\nand "
                "create new container on the '%(image)s' image.\n\n# atomic "
                "update --force %(image)s\n\n removes all containers based on "
                "an image." % {"name": self.name, "image": self.image})

    def container_run_command(self):
        command = "%s run " % sys.argv[0]
        if self.spc:
            command += "--spc "

        if self.name != self.image:
            command += "--name %s " % self.name
        command += self.image
        return command

    def run(self):
        missing_RUN = False
        self.inspect = self._inspect_container()
        if self.inspect:
            self._check_latest()
            # Container exists
            if self.inspect["State"]["Running"]:
                return self._running()
            elif not self.args.display:
                return self._start()

        # Container does not exist
        self.inspect = self._inspect_image()
        if not self.inspect:
            if self.args.display:
                return self.display("Need to pull %s" % self.image)

            self.update()
            self.inspect = self._inspect_image()
        if not self.args.nocheck:
            image_id = self.inspect['Id']
            self.check_install(image_id)
        if self.spc:
            if self.command:
                args = self.SPC_ARGS + self.command
            else:
                args = self.SPC_ARGS + self._get_cmd()

            cmd = self.gen_cmd(args)
        else:
            args = self._get_args("RUN")
            if args:
                args += self.command
            else:
                missing_RUN = True
                if self.command:
                    args = self.RUN_ARGS + self.command
                else:
                    args = self.RUN_ARGS + self._get_cmd()

            cmd = self.gen_cmd(args)
            self.display(cmd)
            if self.args.display:
                return

            if missing_RUN:
                subprocess.check_call(cmd, env=self.cmd_env,
                                      shell=True, stderr=DEVNULL,
                                      stdout=DEVNULL)
                return self._start()

        self.display(cmd)
        if not self.args.display:
            subprocess.check_call(cmd, env=self.cmd_env, shell=True)

    def scan(self):
        self.ping()
        BUS_NAME = "org.OpenSCAP.daemon"
        OBJECT_PATH = "/OpenSCAP/daemon"
        INTERFACE = "org.OpenSCAP.daemon.Interface"

        if self.args.images:
            scan_list = self._get_all_image_ids()
        elif self.args.containers:
            scan_list = self._get_all_container_ids()
        elif self.args.all:
            cids = self._get_all_container_ids()
            iids = self._get_all_image_ids()
            scan_list = cids + iids
        else:
            scan_list = []
            for scan_input in self.args.scan_targets:
                scan_list.append(self.get_input_id(scan_input))
        util.writeOut("\nScanning...\n")
        bus = dbus.SystemBus()
        try:
            oscap_d = bus.get_object(BUS_NAME, OBJECT_PATH)
            oscap_i = dbus.Interface(oscap_d, INTERFACE)
            scan_return = json.loads(oscap_i.scan_list(scan_list, 4))
        except dbus.exceptions.DBusException:
            error = "Unable to find the openscap-daemon dbus service. "\
                    "Either start the openscap-daemon service or pull and run"\
                    " the openscap-daemon image"
            sys.stderr.write("\n{0}\n\n".format(error))
            sys.exit(1)

        if self.args.json:
            util.output_json(scan_return)

        else:
            if not self.args.detail:
                clean = util.print_scan_summary(scan_return)
            else:
                clean = util.print_detail_scan_summary(scan_return)
            if not clean:
                sys.exit(1)

    def stop(self):
        self.inspect = self._inspect_container()
        if self.inspect is None:
            self.inspect = self._inspect_image()
            if self.inspect is None:
                raise ValueError("Container/Image '%s' does not exists" %
                                 self.name)

        args = self._get_args("STOP")
        if args:
            cmd = self.gen_cmd(args)
            self.display(cmd)
            subprocess.check_call(cmd, env=self.cmd_env, shell=True)

        # Container exists
        try:
            if self.inspect["State"]["Running"]:
                self.d.stop(self.name)
        except KeyError:
            pass

    def _rpmostree(self, args):
        aargs = self.args.args
        if len(aargs) > 0 and aargs[0] == "--":
            aargs = aargs[1:]
        os.execl("/usr/bin/rpm-ostree", "rpm-ostree", *(args + aargs))

    def host_status(self):
        argv = ["status"]
        if self.args.pretty:
            argv.append("--pretty")
        self._rpmostree(argv)

    def host_upgrade(self):
        argv = ["upgrade"]
        if self.args.reboot:
            argv.append("--reboot")
        if self.args.os:
            argv.append("--os=" % self.args.os )
        if self.args.diff:
            argv.append("--check-diff")
        if self.args.downgrade:
            argv.append("--allow-downgrade")
        self._rpmostree(argv)

    def host_rollback(self):
        argv = ["rollback"]
        if self.args.reboot:
            argv.append("--reboot")
        self._rpmostree(argv)

    def host_rebase(self):
        argv = ["rebase", self.args.refspec]
        if self.args.os:
            argv.append("--os=" % self.args.os )
        self._rpmostree(argv)

    def uninstall(self):
        self.inspect = self._inspect_container()
        if self.inspect and self.force:
            self.force_delete_containers()
        try:
            # Attempt to remove container, if it exists just return
            self.d.stop(self.name)
            self.d.remove_container(self.name)
        except:
            # On exception attempt to remove image
            pass

        self.inspect = self._inspect_image()
        if not self.inspect:
            raise ValueError("Image '%s' is not installed" % self.image)

        args = self._get_args("UNINSTALL")
        if args:
            cmd = self.gen_cmd(args + list(map(pipes.quote, self.args.args)))
            self.display(cmd)
            subprocess.check_call(cmd, env=self.cmd_env, shell=True)

        if self.name == self.image:
            self.writeOut("/usr/bin/docker rmi %s" % self.image)
            subprocess.check_call(["/usr/bin/docker", "rmi", self.image])

        # Remove the image from atomic.d/install
        image_id = self.inspect['Id']
        self.remove_install(image_id)

    @property
    def cmd_env(self):
        env = dict(os.environ)
        env.update({'NAME': self.name,
                    'IMAGE': self.image})

        if hasattr(self.args, 'opt1') and self.args.opt1:
            env['OPT1'] = self.args.opt1

        if hasattr(self.args, 'opt2') and self.args.opt2:
            env['OPT2'] = self.args.opt2

        if hasattr(self.args, 'opt3') and self.args.opt3:
            env['OPT3'] = self.args.opt3

        default_uid = "0"
        with open("/proc/self/loginuid") as f:
            default_uid = f.readline()

        if "SUDO_UID" in os.environ:
            env["SUDO_UID"] = os.environ["SUDO_UID"]
        else:
            env["SUDO_UID"] = default_uid

        if 'SUDO_GID' in os.environ:
            env['SUDO_GID'] = os.environ['SUDO_GID']
        else:
            try:
                env['SUDO_GID'] = str(pwd.getpwuid(int(env["SUDO_UID"]))[3])
            except:
                env["SUDO_GID"] = default_uid

        return env

    def gen_cmd(self, cargs):
        args = []
        for c in cargs:
            if c == "IMAGE":
                args.append(self.image)
                continue
            if c == "IMAGE=IMAGE":
                args.append("IMAGE=%s" % self.image)
                continue
            if c == "NAME=NAME":
                args.append("NAME=%s" % self.name)
                continue
            if c == "NAME":
                args.append(self.name)
                continue
            args.append(c)
        return " ".join(args)

    def info(self):
        """
        Retrieve and print all LABEL information for a given image.
        """
        def _no_such_image():
            raise ValueError('Could not find any image matching "{}".'
                             ''.format(self.args.image))

        inspection = None
        if not self.args.force_remote_info:
            try:
                inspection = self.d.inspect_image(self.args.image)
            except docker.errors.APIError:
                # No such image locally, but fall back to remote
                pass
        if inspection is None:
            try:
                # Shut up pylint in case we're on a machine with upstream
                # docker-py, which lacks the remote keyword arg.
                #pylint: disable=unexpected-keyword-arg
                inspection = self.d.inspect_image(self.args.image, remote=True)
            except docker.errors.APIError:
                # image does not exist on any configured registry
                _no_such_image()
            except TypeError:  # pragma: no cover
                # If a user doesn't have remote-inspection, setting remote=True
                # above will raise TypeError.
                # TODO: remove if remote inspection is accepted into docker
                # But we should error if the user specifically requested remote
                if self.args.force_remote_info:
                    raise ValueError('Your docker daemon does not support '
                                     'remote inspection.')
                else:
                    _no_such_image()
        # By this point, inspection cannot be "None"
        try:
            labels = inspection['Config']['Labels']
        except TypeError:  # pragma: no cover
            # Some images may not have a 'Labels' key.
            raise ValueError('{} has no label information.'
                             ''.format(self.args.image))
        if labels is not None:
            for label in labels:
                self.writeOut('{0}: {1}'.format(label, labels[label]))

    def dangling(self, image):
        if image == "<none>":
            return "*"
        return " "

    def images(self):
        if self.args.prune:
            cmd = "/usr/bin/docker images --filter dangling=true -q".split()
            for i in subprocess.check_output(cmd, stderr=DEVNULL).split():
                self.d.remove_image(i, force=True)
            return

        self.writeOut(" %-35s %-19s %.12s            %-19s %-10s" %
                      ("REPOSITORY", "TAG", "IMAGE ID", "CREATED",
                       "VIRTUAL SIZE"))

        for image in self.get_images():
            repo, tag = image["RepoTags"][0].split(":")
            self.writeOut(
                "%s%-35s %-19s %.12s        %-19s %-12s" %
                (self.dangling(repo), repo, tag, image["Id"],
                 time.strftime("%F %H:%M",
                               time.localtime(image["Created"])),
                 convert_size(image["VirtualSize"])))

    def install(self):
        self.inspect = self._inspect_image()
        if not self.inspect:
            if self.args.display:
                self.display("Need to pull %s" % self.image)
                return
            self.update()
            self.inspect = self._inspect_image()

        args = self._get_args("INSTALL")
        if not args:
            args = self.INSTALL_ARGS

        cmd = self.gen_cmd(args + list(map(pipes.quote, self.args.args)))

        self.display(cmd)
        image_id = self.inspect['Id']
        self.set_install(image_id)
        if not self.args.display:
            return subprocess.check_call(cmd, env=self.cmd_env, shell=True)


    def help(self):
        if os.path.exists("/usr/bin/rpm-ostree"):
            return _('Atomic Management Tool')
        else:
            return _('Atomic Container Tool')

    def print_spc(self):
        return " ".join(self.SPC_ARGS)

    def print_run(self):
        return " ".join(self.RUN_ARGS)

    def print_install(self):
        return " ".join(self.INSTALL_ARGS) + " /usr/bin/INSTALLCMD"

    def print_uninstall(self):
        return " ".join(self.INSTALL_ARGS) + " /usr/bin/UNINSTALLCMD"

    def _get_layer(self, image):
        def get_label(label):
            return self.get_label(label, image["Id"])
        image = self._inspect_image(image)
        if not image:
            raise ValueError("Image '%s' does not exist" % self.image)
        version = ("%s-%s-%s" % (get_label("Name"), get_label("Version"),
                                 get_label("Release"))).strip("-")
        return({"Id": image['Id'], "Name": get_label("Name"),
                "Version": version, "Tag": find_repo_tag(self.d, image['Id']),
                "Parent": image['Parent']})

    def get_layers(self):
        layers = []
        layer = self._get_layer(self.image)
        layers.append(layer)
        while layer["Parent"] != "":
            layer = self._get_layer(layer["Parent"])
            layers.append(layer)
        return layers

    def _get_all_image_ids(self):
        iids = []
        for image in self.get_images():
            iids.append(image['Id'])
        return iids

    def _get_all_container_ids(self):
        cids = []
        for con in self.get_containers():
            cids.append(con['Id'])
        return cids

    def _get_image_infos(self, image):
        def get_label(label):
            return self.get_label(label, image["Id"])

        return {"Id": image['Id'], "Name": get_label("Name"),
                "Version": ("%s-%s-%s" % (get_label("Name"),
                                          get_label("Version"),
                                          get_label("Release"))).strip(":"),
                "Tag": image["RepoTags"][0]}

    def get_image_infos(self):
        if len(self._images) > 0:
            return self._images

        images = self.get_images()
        for image in images:
            self._images.append(self._get_image_infos(image))

        return self._images

    def verify(self):
        def get_label(label):
            val = self._get_args(label)
            if val:
                return val[0]
            return ""
        self.inspect = self._inspect_image()
        if not self.inspect:
            raise ValueError("Image %s does not exist" % self.image)
        current_name = get_label("Name")
        version = ""
        if current_name:
            version = "%s-%s-%s" % (current_name, get_label("Version"),
                                    get_label("Release"))

        name = None
        buf = ""
        for layer in self.get_layers():
            if name == layer["Name"]:
                continue
            name = layer["Name"]
            if len(name) > 0:
                for i in self.get_image_infos():
                    if i["Name"] == name:
                        if i["Version"] > layer["Version"]:
                            buf = ("Image '%s' contains a layer '%s' that is "
                                   "out of date.\nImage version '%s' is "
                                   "available, current version could contain "
                                   "vulnerabilities." % (self.image,
                                                         layer["Version"],
                                                         i["Version"]))
                            buf += ("You should rebuild the '%s' image using "
                                    "docker build." % (self.image))
                            break
        return buf

    def print_verify(self):
        self.writeOut(self.verify())

    def mount(self):
        if os.geteuid() != 0:
            raise ValueError("This command must be run as root.")
        try:
            options = [opt for opt in self.args.options.split(',') if opt]
            mount.DockerMount(self.args.mountpoint,
                              self.args.live).mount(self.args.image, options)

            # only need to bind-mount on the devicemapper driver
            if self.d.info()['Driver'] == 'devicemapper':
                mount.Mount.mount_path(os.path.join(self.args.mountpoint,
                                                    "rootfs"),
                                       self.args.mountpoint, bind=True)

        except mount.MountError as dme:
            raise ValueError(str(dme))

    def unmount(self):
        if os.geteuid() != 0:
            raise ValueError("This command must be run as root.")
        try:
            dev = mount.Mount.get_dev_at_mountpoint(self.args.mountpoint)

            # If there's a bind-mount over the directory, unbind it.
            if dev.rsplit('[', 1)[-1].strip(']') == '/rootfs' \
                    and self.d.info()['Driver'] == 'devicemapper':
                mount.Mount.unmount_path(self.args.mountpoint)

            return mount.DockerMount(self.args.mountpoint).unmount()

        except mount.MountError as dme:
            raise ValueError(str(dme))

    def version(self):
        def get_label(label):
            val = self._get_args(label)
            if val:
                return val[0]
            return ""

        try:
            self.inspect = self.d.inspect_image(self.image)
        except docker.errors.APIError:
            self.update()
            self.inspect = self.d.inspect_image(self.image)

        if self.args.recurse:
            return self.get_layers()
        else:
            return [self._get_layer(self.image)]

    def print_version(self):
        for layer in self.version():
            version = layer["Version"]
            if layer["Version"] == '':
                version = "None"
            self.writeOut("%s %s %s" % (layer["Id"], version, layer["Tag"]))

    def display(self, cmd):
        subprocess.check_call(
            "/bin/echo \"" + cmd + "\"", env=self.cmd_env, shell=True)

    def ping(self):
        '''
        Check if the docker daemon is running; if not, exit with
        message and return code 1
        '''
        try:
            self.d.ping()
        except requests.exceptions.ConnectionError:
            sys.stderr.write("\nUnable to communicate with docker daemon\n")
            sys.exit(1)

    def _is_container(self, identifier):
        '''
        Checks is the identifier is a container ID or container name.  If
        it is, returns the full container ID. Else it will return an
        AtomicError
        '''
        err_append = "Refine your search to narrow results."
        cons = self.get_containers()
        cids = [x['Id'] for x in cons]
        con_index = [i for i, j in enumerate(cids) if j.startswith(identifier)]

        if len(con_index) > 0:
            if len(con_index) > 1:
                CIDS = []
                for index in con_index:
                    CIDS.append(cids[index])
                raise ValueError("Found multiple container IDs ({0}) that "
                                 " might match '{1}'. {2}"
                                 .format(" ".join(CIDS), identifier,
                                         err_append))
            return cids[con_index[0]]

        for con in cons:
            if "/{0}".format(identifier) in con['Names']:
                return con['Id']

        # No dice
        raise AtomicError

    def _is_image(self, identifier):
        '''
        Checks is the identifier is a image ID or a matches an image name.
        If it finds a match, it returns the full image ID. Else it will
        return an AtomicError.
        '''
        err_append = "Refine your search to narrow results."
        image_info = self.get_images()
        iids = [x['Id'] for x in image_info]
        image_index = [i for i, j in enumerate(iids)
                       if j.startswith(identifier)]

        if len(image_index) > 0:
            if len(image_index) > 1:
                IDS = []
                for index in image_index:
                    IDS.append(iids[index])
                raise ValueError("Found multiple image IDs ({0}) that might "
                                 "match '{1}'. {2}".format(" ".join(IDS),
                                                           identifier,
                                                           err_append))
            return iids[image_index[0]]

        name_search = util.image_by_name(identifier, images=image_info)
        if len(name_search) > 0:
            if len(name_search) > 1:
                tmp_image = dict((x['Id'], x['RepoTags']) for x in image_info)
                repo_tags = []
                for name in name_search:
                    for repo_tag in tmp_image.get(name['Id']):
                        if repo_tag.find(identifier) > -1:
                            repo_tags.append(repo_tag)
                raise ValueError("Found more than one image possibly "
                                 "matching '{0}'. They are:\n    {1} \n{2}"
                                 .format(identifier, "\n    ".join(repo_tags),
                                         err_append))
            return name_search[0]['Id']

        # No dice
        raise AtomicError

    def get_input_id(self, identifier):
        '''
        Determine if the input "identifier" is valid.  Return the container or
        image ID when true and raise a ValueError when not
        '''
        try:
            return self._is_image(identifier)
        except AtomicError:
            pass
        try:
            return self._is_container(identifier)
        except AtomicError:
            pass
        raise ValueError("Unable to associate '{0}' with a container or image."
                         .format(identifier))

    def get_images(self):
        '''
        Wrapper function that should be used instead of querying docker
        multiple times for a list of images.
        '''
        if not self.images_cache:
            self.images_cache = self.d.images()
        return self.images_cache

    def get_containers(self):
        '''
        Wrapper function that should be used instead of querying docker
        multiple times for a list of containers
        '''
        if not self.containers:
            self.containers = self.d.containers(all=True)
        return self.containers


    def check_install(self, iid):
        '''
        Executed prior to atomic run, this function takes an
        image iid and determines if atomic install has been
        run or not. Throws an Error if the image has an
        INSTALL label but cannot find evidence of it ever
        having been installed.
        '''
        if not self._has_install(iid):
            # The image does not have an INSTALL label
            return True

        no_check = 'You can pass --nocheck to atomic run to override this.'

        install_error = ("\n'{0}' has an INSTALL label, which suggests you "
                         "should run 'atomic install' first but we were not "
                         "able to verify if it has been installed prior or "
                         "not.  Either run 'atomic install' or rerun "
                         "'atomic run' with the --nocheck option.\n"
                         .format(self.image))

        if not os.path.exists(self.INSTALL_FILE):
                raise ValueError(install_error)

        try:
            input_data = json.loads(open(self.INSTALL_FILE).read())
            if iid in input_data.keys():
                return True
            else:
                raise ValueError(install_error)
        except ValueError:
            # The file may be present but have nothing in it, which
            # is just fine.
            pass

        # If we get here, we couldn't find any record of it
        raise ValueError(install_error)

    def _has_install(self, docker_id):
        '''
        Returns True or False as to whether the image has a 
        LABEL install
        '''
        if self.get_label('INSTALL', image=docker_id) is not "":
            return True
        else:
            return False

    def set_install(self, iid):
        try:
            install_data = json.loads(open(self.INSTALL_FILE).read())
        except Exception:
            # File does not exist
            install_data = {}
        install_data[iid] = {
                'installed': True,
                'date': str(datetime.today()),
                'image_name': self.image
                }
        with open(self.INSTALL_FILE, 'w') as install_out:
            json.dump(install_data, install_out)

    def remove_install(self, iid):
        try:
            install_data = json.loads(open(self.INSTALL_FILE).read())
            if iid in install_data.keys():
                del install_data[iid]
            # write the file
            with open(self.INSTALL_FILE, 'w') as install_out:
                json.dump(install_data, install_out)
        except Exception:
            # No file, nothing to do
            # No entry, nothing to remove
            return



class AtomicError(Exception):
    pass


def SetFunc(function):
    class customAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            setattr(namespace, self.dest, function)
    return customAction
