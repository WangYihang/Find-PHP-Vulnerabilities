#!/usr/bin/env python
# encoding:utf8

import sublime
import sublime_plugin

import re
import json


class VulnerabilitiesofphpCommand(sublime_plugin.TextCommand):
    def onLoad(self, view):
        self.rules = json.loads(open("rules.json").read())

    def run(self, edit):
        language = "en"  # "zh-cn"
        filename = self.view.file_name()
        suffixes = [
            "php",
            "php3",
            "php4",
            "php5",
            "php7",
            "phps",
            "pht",
            "phtm",
            "phtml",
        ]
        file_extension = filename.split(".")[-1]
        if file_extension in suffixes:
            lines = self.view.substr(sublime.Region(
                0, self.view.size())).split("\n")
            position = 0
            vulnerabilities = []
            line_number = 0
            for line in lines:
                line_number += 1
                for rule in self.rules:
                    result = re.search(rule['reg'], line)
                    if result != None:
                        data = {
                            "filename": filename,
                            "line": line_number,
                            "hint": rule['desc-%s' % (language)],
                        }
                        hint = "\n// Vulnerability: %s\n" % rule['desc-%s' % (language)]
                        self.view.insert(edit, position, hint)
                        position += len(hint)
                        vulnerabilities.append(data)
                position += len(line) + len("\n")
            print(vulnerabilities)
        else:
            print("File extension (%s) not supported!" % (file_extension))
