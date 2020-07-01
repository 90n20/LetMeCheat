# -*- coding: utf-8 -*-
# -----------------------------------------------------------
# Module to handle compression algorithms
#
# (C) 2020 David Rodríguez, Madrid, Spain
# Released under GNU Public License (GPLv3)
# -----------------------------------------------------------

#standard libraries
import logging
import zipfile, tarfile, gzip

#third party libraries
import rarfile

#set logger name
logger = logging.getLogger(__name__)

class CompressedFile():
    """
    Archetype for compressed files handling
    """
    file_type = None

    def __init__(self, f):
        self.f = f
        self.accessor = self.open()
        self.get_content = self.get_content()

    def open(self):
        return None

    def get_content(self):
        return None

class ZIPFile (CompressedFile):
    """
    Zip compressor helper
    """
    file_type = 'zip'

    def open(self):
        return zipfile.ZipFile(self.f)

    def get_content(self):
        """
        Reads compressed file and returns its contents in a list

        :return: List of compressed file contents
        """
        content = []
        file = self.accessor
        for fname in file.namelist():
            entry = file.open(fname)
            if entry is not None:
                fcontent = entry.read()
                content.append(fcontent)
        return content


class RARFile (CompressedFile):
    """
    Rar compression helper
    """
    file_type = 'rar'

    def open(self):
        return rarfile.RarFile(self.f)

    def get_content(self):
        """
        Reads compressed file and returns its contents in a list

        :return: List of compressed file contents
        """
        content = []
        file = self.accessor
        for fname in file.infolist():
            fcontent = file.read(fname)
            if fcontent is not None:
                content.append(fcontent)
        return content

class TARGZFile (CompressedFile):
    """
    Tar/gzip compression helper
    """
    file_type = 'tar.gz'

    def open(self):
        return tarfile.open(self.f, "r:gz")

    def get_content(self):
        content = []
        file = self.accessor
        for c_file in file.getmembers():
            entry = file.extractfile(c_file)
            if entry is not None:
                fcontent = entry.read()
                content.append(fcontent)
        return content

class TARFile (CompressedFile):
    """
    Tar compression helper
    """
    file_type = 'tgz'

    def open(self):
        return tarfile.open(self.f, "r:")

    def get_content(self):
        """
        Reads compressed file and returns its contents in a list

        :return: List of compressed file contents
        """
        content = []
        file = self.accessor
        for c_file in file.getmembers():
            entry = file.extractfile(c_file)
            if entry is not None:
                fcontent = entry.read()
                content.append(fcontent)
        return content