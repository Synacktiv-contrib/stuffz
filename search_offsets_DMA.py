#!/usr/bin/env python
# coding=utf-8

# All credits go to carmaa and his awesome 'inception' project
# (https://github.com/carmaa/inception)
# and to Romain Thomas (https://twitter.com/rh0main) for his
# not less awesome framework "Do you even 'LIEF'?"
# (https://github.com/lief-project/LIEF)

from __future__ import print_function
import hashlib
import argparse
from os import path
from glob import glob
from struct import unpack
import lief


class OS:
    def __init__(self, **kwargs):
        for key, value in kwargs.iteritems():
            if key == "pattern1" or key == "pattern2":
                setattr(self, key, {'offset': value[0], 'opcodes': value[1]})
            else:
                setattr(self, key, value)

    def display(self):
        print("version: %s" % (self.version))
        print("architecture: %s" % (self.architecture))
        print("service_pack: %s" % (self.SP))
        print("pattern1: %s" % (self.pattern1))
        print("pattern2: %s" % (self.pattern2
                                if self.pattern2 is not None else "None"))


def find_offsets(content, pattern1, offset1=None, pattern2=None, offset2=None):
    matches = []
    for i in range(len(content)):
        found = False
        if content[i] == pattern1[0] and content[i:i+len(pattern1)] == pattern1:
            if pattern2 == None:
                found = True
            elif  content[i + offset2:i + offset2+len(pattern2)] == pattern2:
                found = True
        if found == True:
            matches.append(i)
    return matches


def dummy_convert_offsets_to_list_int(value):
    return list(unpack("<" + ("B" * len(value.decode("hex"))), value.decode("hex")))


def initialize_Windows_objects():
    OS_list = {}
    WindowsXP = {}
    opcodes_XP = dummy_convert_offsets_to_list_int("83f8107511b0018b")
    WindowsXP["x86"] = [OS(version="WindowsXP", architecture="x86", SP=["SP2", "SP3"],
                           pattern1=[0, opcodes_XP])]
    OS_list["WindowsXP"] = WindowsXP

    WindowsVista = {}
    opcodes1_Vista_x64 = dummy_convert_offsets_to_list_int("c60f85")
    opcodes2_Vista_x64 = dummy_convert_offsets_to_list_int("b8")
    opcodes_Vista_x86 = dummy_convert_offsets_to_list_int("83f8107513b0018b")

    WindowsVista["x64"] = [OS(version="WindowsVista", architecture="x64", SP="SP2",
                              pattern1=[0, opcodes1_Vista_x64], pattern2=[7, opcodes2_Vista_x64])]
    WindowsVista["x86"] = [OS(version="WindowsVista", architecture="x86",
                              SP=["SP0", "SP1", "SP2"],
                              pattern1=[0, opcodes_Vista_x86])]
    OS_list["WindowsVista"] = WindowsVista

    Windows7 = {}
    opcodes1_7_x64 = dummy_convert_offsets_to_list_int("c60f85")
    opcodes2_7_x64 = dummy_convert_offsets_to_list_int("b8")
    opcodes_7_x86_SP0 = dummy_convert_offsets_to_list_int("83f8107513b0018b")
    opcodes1_7_x86_SP1 = dummy_convert_offsets_to_list_int("83f8100f85")
    opcodes2_7_x86_SP1 = dummy_convert_offsets_to_list_int("b0018b")

    Windows7["x64"] = [OS(version="Windows7", architecture="x64",
                          SP=["SP0","SP1"], pattern1=[0, opcodes1_7_x64],
                          pattern2=[7, opcodes2_7_x64])]
    Windows7["x86"]= [OS(version="Windows7", architecture="x86", SP="SP0",
                         pattern1=[0, opcodes_7_x86_SP0])]
    Windows7["x86"].append(OS(version="Windows7", architecture="x86", SP="SP1",
                              pattern1=[0, opcodes1_7_x86_SP1],
                              pattern2=[9, opcodes2_7_x86_SP1]))
    OS_list["Windows7"] = Windows7

    Windows8 = {}
    opcodes1_8_x64 = dummy_convert_offsets_to_list_int("c60f85")
    opcodes2_8_x64 = dummy_convert_offsets_to_list_int("66b80100")
    opcodes_8_x86 = dummy_convert_offsets_to_list_int("8bff558bec81ec90000000a1")

    Windows8["x64"] = [OS(version="Windows8", architecture="x64", SP="",
                          pattern1=[0, opcodes1_8_x64],
                          pattern2=[7, opcodes2_8_x64])]
    Windows8["x86"] = [OS(version="Windows8", architecture="x86", SP="",
                          pattern1=[0, opcodes_8_x86])]
    OS_list["Windows8"] = Windows8

    Windows8_1 = {}
    opcodes1_8_1_x64 = dummy_convert_offsets_to_list_int("c60f85")
    opcodes2_8_1_x64 = dummy_convert_offsets_to_list_int("66b80100")
    opcodes_8_1_x86 = dummy_convert_offsets_to_list_int("8bff558bec81ec90000000a1")

    Windows8_1["x64"] = [OS(version="Windows8.1", architecture="x64", SP="",
                            pattern1=[0, opcodes1_8_1_x64],
                            pattern2=[7, opcodes2_8_1_x64])]
    Windows8_1["x86"] = [OS(version="Windows8.1", architecture="x86", SP="",
                            pattern1=[0, opcodes_8_1_x86])]
    OS_list["Windows8.1"] = Windows8_1
    return OS_list


def build_new_OS_list(OS_list, version, architecture = None):
    new_OS_list = []
    if architecture is None:
        new_OS_list = {version: OS_list[version]}
    elif architecture in OS_list[version]:
        new_OS_list = {version: {architecture: OS_list[version][architecture]}}
    return new_OS_list


def display_bruteforce_results(bf_results):
    for result in bf_results:
        print("    OS version:      %s" % (result[0].version))
        print("    architecture:    %s" % (result[0].architecture))
        print("    service_pack(s): %s" % (", ".join(result[0].SP)
                                                     if isinstance(result[0].SP, str) == False
                                                     else result[0].SP))
        print("    offset(s):       %s" % (",".join(result[1])))
        print("")


def bruteforce_offsets(content, OS_list):
    results = []
    for OS_version, Windows_object in OS_list.iteritems():
        targets = None
        for architecture, value in Windows_object.iteritems():
            for target in value:
                offsets = []
                patterns = [target.pattern1["opcodes"], target.pattern1["offset"]]
                if hasattr(target, 'pattern2'):
                    patterns.append(target.pattern2["opcodes"])
                    patterns.append(target.pattern2["offset"])
                offsets = find_offsets(content, *patterns)
                if offsets:
                    results.append([target, [hex(x) for x in offsets]])
    return results


def get_text_section_content(input_file):
    binary = lief.parse(input_file)
    sections = binary.sections
    text_section = [section for section in sections if section.name == ".text"][0]
    return text_section.content


def get_version(signature, MS, LS):
    version = ""
    if signature == 0xfeef04bd:
        version = (str((MS >> 16) & 0xffff) + '.' + str((MS >> 0) & 0xffff) +
                  '.' + str((LS >> 16) & 0xffff) + '.' + str((LS >> 0) & 0xffff))
    return version


def parse_arguments():
    parser = argparse.ArgumentParser(description="Script to extract all offsets\
                                     needed by 'inception' tool in order to\
                                     proceed to a DMA attack through FireWire connection,\
                                     by jean-christophe.delaunay <at> synacktiv.com")
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument('--os', required=False,
                        choices=['WindowsXP', 'WindowsVista', 'Windows7',
                                 'Windows8', 'Windows8.1'],
                        help="Specify Windows version which DLL is from")
    parser.add_argument('--archi', required=False, choices=['x86', 'x64'],
                        help="Specify architecture of Windows version")
    group.add_argument('-f', '--file', required=False,
                       help="Dll to search offsets in (msv1_0.dll or \
                       NtlmShared.dll). Cannot be used with '-d'")
    group.add_argument('-d', '--directory', required=False, help="Directory \
                       containing Dlls to search offsets in (msv1_0.dll or \
                       NtlmShared.dll). Cannot be used with '-f'")
    options = parser.parse_args()
    if not any(vars(options).values()):
        parser.print_help()
        exit(1)
    return options


if __name__ == "__main__":
    options = parse_arguments()
    OS_list = initialize_Windows_objects()
    if options.os is not None:
        if options.archi is not None:
            OS_list = build_new_OS_list(OS_list, options.os, options.archi)
        else:
            OS_list = build_new_OS_list(OS_list, options.os)
    if not OS_list:
        print("Could not match provided options with any available Windows\
              os/architecture, exiting.")
        sys.exit(1)
    target = []
    if options.file is not None:
        target.append(options.file)
    elif path.isdir(options.directory):
        target = glob(path.join(options.directory, '*'))
    else:
        print("Error while opening file/dir, exiting.")
        sys.exit(1)
    for myfile in target:
        content = get_text_section_content(myfile)
        results = bruteforce_offsets(content, OS_list)
        pe_parsed = lief.parse(myfile)
        resource = pe_parsed.resources_manager
        file_info = resource.version.fixed_file_info
        file_version =  get_version(file_info.signature, file_info.file_version_MS,
                                    file_info.file_version_LS)
        product_version = get_version(file_info.signature, file_info.product_version_MS,
                                      file_info.product_version_LS)

        print("dll name: %s" % myfile)
        print("  file version:    %s" % file_version)
        print("  product version: %s\n" % product_version)
        with open(myfile, 'rb') as f:
            raw_content = f.read()
            print("  MD5:    %s" % hashlib.new("md5", raw_content).hexdigest())
            print("  SHA1:   %s" % hashlib.new("sha1", raw_content).hexdigest())
            print("  SHA256: %s\n" % hashlib.new("sha256", raw_content).hexdigest())
        display_bruteforce_results(results)
