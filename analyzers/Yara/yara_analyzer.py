#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.analyzer import Analyzer

import os
import yara


class YaraAnalyzer(Analyzer):
    """Checking binaries through yara rules. This analyzer requires a list of yara rule paths in the cortex
    configuration. If a path is given, an index file is expected."""
    def __init__(self):
        Analyzer.__init__(self)

        self.rulepaths = self.get_param('config.rules', None, 'No paths for rules provided.')
        if isinstance(self.rulepaths, str):
            self.rulepaths = [self.rulepaths]

        self.ruleset = []
        for rulepath in self.rulepaths:
            if os.path.isfile(rulepath):
                if rulepath[len(rulepath)-3:] == 'yar':
                    self.ruleset.append(yara.compile(rulepath))
                elif rulepath[len(rulepath)-3:] == 'yas':
                    self.ruleset.append(yara.load(rulepath))
            elif os.path.isdir(rulepath):
                if os.path.isfile(rulepath + '/index.yas'):
                    self.ruleset.append(yara.load(rulepath + '/index.yas'))
                elif os.path.isfile(rulepath + '/index.yar'):
                    self.ruleset.append(yara.compile(rulepath + '/index.yar'))

    def check(self, file):
        """
        Checks a given file against all available yara rules

        :param file: Path to file
        :type file:str
        :returns: Python dictionary containing the results
        :rtype: list
        """
        result = []
        for rule in self.ruleset:
            matches = rule.match(file)
            for match in matches:
                result.append(str(match))

        return result

    def summary(self, raw):
        taxonomies = []
        namespace = "Yara"
        predicate = "Match"

        rules_hit_num = len(raw["results"])
        value = "{} rule(s)".format(rules_hit_num)
        if rules_hit_num == 0:
            level = "safe"
        elif 0 < rules_hit_num < 6:
            level = "suspicious"
        else:
            level = "malicious"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == 'file':
            self.report({'results': self.check(self.get_param('file'))})
        elif self.data_type == 'file_path':
            self.report({'results': self.check(self.get_data())})
        else:
            self.error('Wrong data type.')


if __name__ == '__main__':
    YaraAnalyzer().run()
