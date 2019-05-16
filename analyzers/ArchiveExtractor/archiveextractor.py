#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import os
import tempfile
import kai
import hashlib
import magic

class ArchiveExtractorAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        # filename of the observable
        self.filename = self.getParam('attachment.name', 'noname.ext')

        self.filepath = self.getParam('file', None, 'File is missing')

    def run(self):
        if self.data_type == 'file':
            try:
                parsingResult = extractArchive(self.filepath)
                self.report(parsingResult)
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "ArchiveExtractor"
        predicate = "Extracted Files"
        value = "\"0\""

        if "attachments" in raw:
            value = len(raw["extracted_files"])
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}


def extractArchive(filepath):
    result = dict()
    result['extracted_files'] = list()

    try:
        dest_tmp_dir = tempfile.TemporaryDirectory().name
        kai.extract(filepath, dest_tmp_dir)

        filefullpaths = []
        for root, directories, filenames in os.walk(dest_tmp_dir):
            for filename in filenames:
                filefullpaths.append(os.path.join(root, filename))

        for extracted_filepath in filefullpaths:
            extracted_file = dict()
            extracted_file['filepath'] = extracted_filepath
            fname, extension = os.path.splitext(extracted_filepath)
            extracted_file['filename'] = os.path.basename(extracted_filepath)
            extracted_file['extension'] = extension[1:]
            extracted_file['mime'] = magic.from_file(extracted_filepath, mime=True)

            with open(extracted_filepath, 'rb') as inputfile:
                data = inputfile.read()
                extracted_file['md5'] = str(hashlib.md5(data).hexdigest())
                extracted_file['sha1'] = str(hashlib.sha1(data).hexdigest())
                extracted_file['sha256'] = str(hashlib.sha256(data).hexdigest())

            result['extracted_files'].append(extracted_file)
    except KeyError as e:
        pass

    return result


if __name__ == '__main__':
    ArchiveExtractorAnalyzer().run()