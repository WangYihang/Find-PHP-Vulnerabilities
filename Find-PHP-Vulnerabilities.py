#!/usr/bin/env python
# encoding:utf8

import sublime
import sublime_plugin

import re

rules = [
    {
        "desc-zh-cn": "文件包含函数中存在变量,可能存在文件包含漏洞",
        "reg": "\\b(include|require)(_once){0,1}(\\s{1,5}|\\s{0,5}\\().{0,60}\\$(?!.*(this->))\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}",
        "desc-en": "(LFI/RFI) Controllable variables in file inclusion functions."
    },
    {
        "desc-zh-cn": "preg_replace的/e模式，且有可控变量，可能存在代码执行漏洞",
        "reg": "\\bpreg_replace\\(\\s{0,5}.*/[is]{0,2}e[is]{0,2}[\"']\\s{0,5},(.*\\$.*,|.*,.*\\$)",
        "desc-en": "(RCE) preg_replace works in \"/e\" mode with controllable variables."
    },
    {
        "desc-zh-cn": "phpinfo()函数，可能存在敏感信息泄露漏洞",
        "reg": "\\bphpinfo\\s{0,5}\\(\\s{0,5}\\)",
        "desc-en": "(Info Leak) phpinfo"
    },
    {
        "desc-zh-cn": "call_user_func函数参数包含变量，可能存在代码执行漏洞",
        "reg": "\\bcall_user_func(_array){0,1}\\(\\s{0,5}\\$\\w{1,15}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}",
        "desc-en": "(RCE) variables of call_user_func are controllable."
    },
    {
        "desc-zh-cn": "读取文件函数中存在变量，可能存在任意文件读取漏洞",
        "reg": "\\b(file_get_contents|fopen|readfile|fgets|fread|parse_ini_file|highlight_file|fgetss|show_source)\\s{0,5}\\(.{0,40}\\$\\w{1,15}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}",
        "desc-en": "(Arbitry File Read) variables of file-reading functions are controllable."
    },
    {
        "desc-zh-cn": "命令执行函数中存在变量，可能存在任意命令执行漏洞",
        "reg": "\\b(system|passthru|pcntl_exec|shell_exec|escapeshellcmd|exec)\\s{0,10}\\(.{0,40}\\$\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}",
        "desc-en": "(RCE) Controllable variables in system command functions leads to arbitrary command execution."
    },
    {
        "desc-zh-cn": "parse_str函数中存在变量,可能存在变量覆盖漏洞",
        "reg": "\\b(mb_){0,1}parse_str\\s{0,10}\\(.{0,40}\\$\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}",
        "desc-en": "(variable Override) Params of function parse_str are under control, leads to variable override vulnerability."
    },
    {
        "desc-zh-cn": "双$$符号可能存在变量覆盖漏洞",
        "reg": "\\${{0,1}\\$\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}\\s{0,4}=\\s{0,4}.{0,20}\\$\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}",
        "desc-en": "(variable Override) Syntax $$ leads to variable override vulnerability."
    },
    {
        "desc-zh-cn": "获取IP地址方式可伪造，HTTP_REFERER可伪造，常见引发SQL注入等漏洞",
        "reg": "[\"'](HTTP_CLIENT_IP|HTTP_X_FORWARDED_FOR|HTTP_REFERER)[\"']",
        "desc-en": "(SQLI) The method of obtaining client IP is vulnerablity, the IP address can be fake, maybe leads to SQL injection vulnerabilities."
    },
    {
        "desc-zh-cn": "文件操作函数中存在变量，可能存在任意文件读取/删除/修改/写入等漏洞",
        "reg": "\\b(unlink|copy|fwrite|file_put_contents|bzopen)\\s{0,10}\\(.{0,40}\\$\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}",
        "desc-en": "(File Operations) Params of file operate functions (fwrite / file_put_contents...) are under control, leads to Arbitry file write/read/modify/delete vulnerabilities."
    },
    {
        "desc-zh-cn": "extract函数中存在变量，可能存在变量覆盖漏洞",
        "reg": "\\b(extract)\\s{0,5}\\(.{0,30}\\$\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}\\s{0,5},{0,1}\\s{0,5}(EXTR_OVERWRITE){0,1}\\s{0,5}\\)",
        "desc-en": "(variable Override) Params of function extract are under control, leads to variable override vulnerability."
    },
    {
        "desc-zh-cn": "可能存在代码执行漏洞,或者此处是后门",
        "reg": "\\$\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}\\s{0,5}\\(\\s{0,5}\\$_(POST|GET|REQUEST|SERVER)\\[.{1,20}\\]",
        "desc-en": "(RCE) Backdoor / Webshell"
    },
    {
        "desc-zh-cn": "urldecode绕过GPC,stripslashes会取消GPC转义字符",
        "reg": "^(?!.*\\baddslashes).{0,40}\\b((raw){0,1}urldecode|stripslashes)\\s{0,5}\\(.{0,60}\\$\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}",
        "desc-en": "(SQLI) urldecode bypass GPC, stripslashes function will clean the escape characters"
    },
    {
        "desc-zh-cn": "``反引号中包含变量，变量可控会导致命令执行漏洞",
        "reg": "`\\$\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}`",
        "desc-en": "(RCE) Params of syntax ``  are under control, leads to remote command execution vulnerability."
    },
    {
        "desc-zh-cn": "array_map参数包含变量，变量可控可能会导致代码执行漏洞",
        "reg": "\\barray_map\\s{0,4}\\(\\s{0,4}.{0,20}\\$\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}\\s{0,4}.{0,20},",
        "desc-en": "(RCE) Params of function array_map are under control, leads to remote code execution vulnerability."
    },
    {
        "desc-zh-cn": "SQL语句select中条件变量无单引号保护，可能存在SQL注入漏洞",
        "reg": "select\\s{1,4}.{1,60}from.{1,50}\\bwhere\\s{1,3}.{1,50}=[\"\\s\\.]{0,10}\\$\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}",
        "desc-en": "(SQLI) Params of SQL in function select are not surrounded with single quotes, may leads to SQL injection vulnerabilities."
    },
    {
        "desc-zh-cn": "SQL语句delete中条件变量无单引号保护，可能存在SQL注入漏洞",
        "reg": "delete\\s{1,4}from.{1,20}\\bwhere\\s{1,3}.{1,30}=[\"\\s\\.]{0,10}\\$\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}",
        "desc-en": "(SQLI) Params of SQL in function delete are not surrounded with single quotes, may leads to SQL injection vulnerabilities."
    },
    {
        "desc-zh-cn": "SQL语句insert中插入变量无单引号保护，可能存在SQL注入漏洞",
        "reg": "insert\\s{1,5}into\\s{1,5}.{1,60}\\$\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}",
        "desc-en": "(SQLI) Params of SQL in function insert are not surrounded with single quotes, may leads to SQL injection vulnerabilities."
    },
    {
        "desc-zh-cn": "SQL语句delete中条件变量无单引号保护，可能存在SQL注入漏洞",
        "reg": "update\\s{1,4}.{1,30}\\s{1,3}set\\s{1,5}.{1,60}\\$\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}",
        "desc-en": "(SQLI) Params of SQL in function update are not surrounded with single quotes, may leads to SQL injection vulnerabilities."
    },
    {
        "desc-zh-cn": "eval或者assertc函数中存在变量，可能存在代码执行漏洞",
        "reg": "\\b(eval|assert)\\s{0,10}\\(.{0,60}\\$\\w{1,20}((\\[[\"']|\\[)\\${0,1}[\\w\\[\\]\"']{0,30}){0,1}",
        "desc-en": "(RCE) Params of syntax or and assert are under control, leads to remote code execution vulnerability."
    },
    {
        "desc-zh-cn": "echo等输出中存在可控变量，可能存在XSS漏洞",
        "reg": "\\b(echo|print|print_r)\\s{0,5}\\({0,1}.{0,60}\\$_(POST|GET|REQUEST|SERVER)",
        "desc-en": "(XSS) Params of syntax echo are under control, leads to XSS vulnerability."
    },
    {
        "desc-zh-cn": "header函数或者js location有可控参数，存在任意跳转或http头污染漏洞",
        "reg": "(\\bheader\\s{0,5}\\(.{0,30}|window.location.href\\s{0,5}=\\s{0,5})\\$_(POST|GET|REQUEST|SERVER)",
        "desc-en": "(HTTP Parameter pollution) Params of function header are under control, leads to HTTP Parameter pollution vulnerability or Arbitry redirection vulnerability."
    },
    {
        "desc-zh-cn": "存在文件上传，注意上传类型是否可控",
        "reg": "\\bmove_uploaded_file\\s{0,5}\\(",
        "desc-en": "(File upload) Params of function header are under control, maybe leads to RCE / DoS"
    }
]


class VulnerabilitiesofphpCommand(sublime_plugin.TextCommand):
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
                for rule in rules:
                    result = re.search(rule['reg'], line)
                    if result != None:
                        data = {
                            "filename": filename,
                            "line": line_number,
                            "hint": rule['desc-%s' % (language)],
                        }
                        hint = "\n// Vulnerability: %s\n" % rule['desc-%s' % (
                            language)]
                        self.view.insert(edit, position, hint)
                        position += len(hint)
                        vulnerabilities.append(data)
                position += len(line) + len("\n")
            print(vulnerabilities)
        else:
            print("File extension (%s) not supported!" % (file_extension))
