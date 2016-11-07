from abc import abstractmethod, ABCMeta, abstractproperty


class Backend(object): #pylint: disable=metaclass-assignment
    # Mark the class as abstract
    __metaclass__ = ABCMeta

    @abstractproperty
    def backend(self):
        return 'Should never use this'

    @abstractmethod
    def inspect_image(self, image):
        """
        Returns the results of an inspected image as an image object
        :param image:
        :return: img_obj
        """
        pass

    @abstractmethod
    def inspect_container(self, container):
        """
        Inspect a container
        :param container:
        :return: con_obj
        """
        pass

    @abstractmethod
    def pull_image(self, image):
        """
        Pulls an image to the backend
        :param image:
        :return:
        """
        pass

    @abstractmethod
    def install(self, image, name):
        """
        Installs an image on a backend
        :param image:
        :param name:
        :return:
        """
        pass

    @abstractmethod
    def uninstall(self, name):
        """
        Uninstalls an image from a backend
        :param name:
        :return:
        """
        pass

    @abstractmethod
    def version(self, image):
        """
        Return a list of layer objects
        :param image:
        :return:  list of layer objects
        """
        pass

    @abstractmethod
    def update(self, name, force=False):
        pass

    @abstractmethod
    def get_containers(self):
        """
        Get containers for the backend
        :return: list of container objects
        """
        pass

    @abstractmethod
    def get_images(self, get_all=False):
        """
        Get images for the backend
        :param get_all: bool
        :return:  list of image objects
        """
        pass

    @abstractmethod
    def delete_image(self, image, force=False):
        """
        Delete image
        :param image:
        :param force:
        :return:
        """
        pass

    @abstractmethod
    def start_container(self, name):
        pass

    @abstractmethod
    def stop_container(self, name):
        pass

    @abstractmethod
    def prune(self):
        pass

    @abstractmethod
    def has_image(self, img):
        pass

    @abstractmethod
    def has_container(self, container):
        pass

    @abstractmethod
    def validate_layer(self, layer):
        pass

