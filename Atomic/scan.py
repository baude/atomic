from . import Atomic
from . import util
from datetime import datetime
import os
from shutil import rmtree
import json


class Scan(Atomic):
    """
    Scan class that can generically work any scanner
    """
    DEBUG = False
    results = '/var/lib/atomic'

    def __init__(self):
        super(Scan, self).__init__()
        self.scan_dir = None
        self.rootfs_paths = []
        self.cur_time = datetime.now().strftime('%Y-%m-%d-%H-%M-%S-%f')
        self.chroot_dir = '/run/atomic/{}'.format(self.cur_time)
        self.results_dir = None
        self.scan_content = {}

    def scan(self):

        # Load the atomic config file and check scanner settings
        yaml_error = "The image name or scanner arguements for '{}' is not " \
                     "defined in /etc/atomic.conf".format(self.args.scanner)
        scanner_image_name = self.get_atomic_config_item(['scanners',
                                                          self.args.scanner,
                                                          'image_name'])
        scanner_args = self.get_atomic_config_item(['scanners',
                                                    self.args.scanner,
                                                    'scanner_args'])
        custom_docker_args = self.get_atomic_config_item(['scanners',
                                                          self.args.scanner,
                                                          'docker_args'])
        custom_docker_args = [''] if custom_docker_args is None \
            else custom_docker_args

        if not isinstance(custom_docker_args, list):
            raise ValueError("The custom docker arguements for {} must be in"
                             " list ([]) form.".format(self.args.scanner))

        if not isinstance(scanner_args, list):
            raise ValueError("The scanner arguements for {} must be in list"
                             " ([]) form.".format(self.args.scanner))

        if None in [scanner_image_name, scanner_args]:
            raise ValueError(yaml_error)

        self.results_dir = os.path.join(self.results, self.args.scanner, self.cur_time)
        scan_list = self._get_scan_list()
        for i in scan_list:
            self.scan_content[i['Id']] = i.get('input')

        # mount all the rootfs
        self._mount_scan_rootfs(scan_list)

        docker_args = ['docker', 'run', '-it', '--rm', '-v', '/etc/localtime:/etc/localtime',
                       '-v', '{}:{}'.format(self.chroot_dir, '/scanin'), '-v',
                       '{}:{}'.format(self.results_dir, '/scanout')]

        # Assemble the cmd line for the scan
        scan_cmd = docker_args
        if len(custom_docker_args) > 1:
            scan_cmd = scan_cmd + custom_docker_args
        scan_cmd = scan_cmd + [scanner_image_name] + scanner_args

        # Show the command being run
        util.writeOut(" ".join(scan_cmd))

        # do the scan
        util.check_call(scan_cmd)

        # umount all the rootfs
        self._umount_rootfs_in_dir()

        # output results
        self.output_results()

        # record environment
        self.record_environment()

    def _get_scan_list(self):

        def gen_images():
            slist = []
            for x in self.get_images():
                x['input'] = x['Id']
                slist.append(x)
            return slist

        def gen_containers():
            slist = []
            for x in self.get_containers():
                x['input'] = x['Id']
                slist.append(x)
            return slist

        if self.args.images:
            scan_list = gen_images()
        elif self.args.containers:
            scan_list = gen_containers()
        elif self.args.all:
            scan_list = gen_containers() + gen_images()
        else:
            scan_list = []
            images = self.get_images()
            containers = self.get_containers()
            for scan_input in self.args.scan_targets:
                docker_object = (next((item for item in containers
                                       if item['Id'] == self.get_input_id(scan_input)), None))
                docker_object = docker_object if docker_object is not None \
                    else (next((item for item in images if item['Id'] == self.get_input_id(scan_input)), None))
                docker_object['input'] = scan_input
                scan_list.append(docker_object)

        return scan_list

    def _mount_scan_rootfs(self, scan_list):
        if not os.path.exists(self.chroot_dir):
            os.makedirs(self.chroot_dir)
        if self.DEBUG:
            util.writeOut("Created {}".format(self.chroot_dir))
        for docker_object in scan_list:
            mount_path = os.path.join(self.chroot_dir, docker_object['Id'])
            os.mkdir(mount_path)
            if self.DEBUG:
                util.writeOut("Created {}".format(mount_path))
            self.mount(mountpoint=mount_path, docker_object=docker_object['Id'])
            if self.DEBUG:
                util.writeOut("Mounted {} to {}".format(docker_object, mount_path))

    def _umount_rootfs_in_dir(self):
        for _dir in self.get_rootfs_paths():
            rootfs_dir = os.path.join(self.chroot_dir, _dir)
            self.unmount(rootfs_dir)

            # Clean up temporary containers

            if not self.DEBUG:
                # Remove the temporary container dirs
                rmtree(rootfs_dir)
            else:
                util.writeOut("Unmounted {}".format(rootfs_dir))
        if not self.DEBUG:
            rmtree(self.chroot_dir)

    def get_rootfs_paths(self):
        """
        Returns the list of rootfs paths (not fully qualified); if defined,
        returns self.rootfs_paths, else defines and returns it
        :return: list
        """
        def _get_rootfs_paths():
            return next(os.walk(self.chroot_dir))[1]

        if len(self.rootfs_paths) < 1:
            self.rootfs_paths = _get_rootfs_paths()
        return self.rootfs_paths

    def output_results(self):
        """
        Write results of the scan to stdout
        :return: None
        """
        json_files = self._get_json_files()
        for json_file in json_files:
            json_results = json.load(open(json_file))
            uuid = os.path.basename(json_results['UUID'])
            name1 = self._get_input_name_for_id(uuid)
            if not self._is_iid(uuid):
                name2 = uuid[:15]
            else:
                # Containers do not have repo names
                if uuid not in [x['Id'] for x in self.get_containers()]:
                    name2 = self._get_repo_names(uuid)
                else:
                    name2 = uuid[:15]
            util.writeOut("\n{} ({})\n".format(name1, name2))
            if json_results['Successful'].upper() == "FALSE":
                util.writeOut("{}{} is not supported for this scan."
                              .format(' ' * 5, self._get_input_name_for_id(uuid)))
            elif len(json_results['Vulnerabilities']) > 0:
                util.writeOut("The following issues were found:\n")
                for vul in json_results['Vulnerabilities']:
                    util.writeOut("{}{}".format(' ' * 5, vul['Title']))
                    util.writeOut("{}Severity: {}".format(' ' * 5, vul['Severity']))
                    if 'Custom' in vul.keys() and len(vul['Custom']) > 1:
                        custom_field = vul['Custom']
                        self._output_custom(custom_field, 7)
                    util.writeOut("")
            else:
                util.writeOut("{} passed the scan".format(self._get_input_name_for_id(uuid)))
        util.writeOut("\nFiles associated with this scan are in {}.\n".format(self.results_dir))

    def _output_custom(self, value, indent):
        space = ' ' * indent
        next_indent = indent + 2
        if isinstance(value, dict):
            for x in value:
                if isinstance(value[x], dict):
                    util.writeOut("{}{}:".format(space, x))
                    self._output_custom(value[x], next_indent)
                elif isinstance(value[x], list):
                    util.writeOut("{}{}:".format(space, x))
                    self._output_custom(value[x], next_indent)
                else:
                    util.writeOut("{}{}: {}".format(space, x, value[x]))
        elif isinstance(value, list):
            for x in value:
                if isinstance(x, dict):
                    self._output_custom(x, next_indent)
                elif isinstance(x, list):
                    self._output_custom(x, next_indent)
                else:
                    util.writeOut('{}{}'.format(space, x))

    def _get_json_files(self):
        json_files = []
        for files in os.walk(self.results_dir):
            for jfile in files[2]:
                if jfile == 'json':
                    json_files.append(os.path.join(files[0], jfile))
        return json_files

    def _get_input_name_for_id(self, iid):
        return self.scan_content[iid]

    def _is_iid(self, input_name):
        if input_name.startswith(self.scan_content[input_name]):
            return True
        return False

    def _get_repo_names(self, docker_id):
        _match = next((x for x in self.get_images() if x['Id'] == docker_id), None)
        if _match is None:
            _match = next((x for x in self.get_containers() if x['Id'] == docker_id), None)
        if'<none>' in _match['RepoTags'][0]:
            return docker_id[:15]
        else:
            return ', '.join(_match['RepoTags'])

    def record_environment(self):
        """
        Grabs a "snapshot" the results of docker info and inspect results for
        all images and containers.  Write it to results_dir/environment.json
        :return: None
        """

        environment = {}
        environment['info'] = self.d.info()
        environment['images'] = []
        for iid in [x['Id'] for x in self.get_images()]:
            environment['images'].append(self._inspect_image(image=iid))

        environment['containers'] = []
        for cid in [x['Id'] for x in self.get_containers()]:
            environment['containers'].append(self._inspect_container(name=cid))

        with open(os.path.join(self.results_dir, 'environment.json'), 'w') as f:
            json.dump(environment, f, indent=4, separators=(',', ': '))
