#!/usr/bin/env python3
"""
    PocketBook SWUPDATE.BIN parser script
    Copyright 2018 Synacktiv

    Usage: compile the KSY file with kaitai-struct-compiler and then use
    this script to parse / dump the pocketbook firmware update file

    Licensed under the "THE BEER-WARE LICENSE" (Revision 42):
    yourname wrote this file. As long as you retain this notice you
    can do whatever you want with this stuff. If we meet some day, and you think
    this stuff is worth it, you can buy me a beer or coffee in return

"""

import argparse
import base64
import binascii
import mmap
import os.path
from hashlib import md5, sha256

from kaitaistruct import KaitaiStream

from pocketbook_swupdate import PocketbookSwupdate


class MMap:
    """Easy-to-use wrapper for mmap. This class is licensed under Unlicense by KOLANICH"""

    __slots__ = ("path", "f", "m")

    def __init__(self, path):
        self.path = path
        self.f = None
        self.m = None

    def __enter__(self):
        self.f = open(self.path, "rb").__enter__()
        self.m = mmap.mmap(self.f.fileno(), 0, prot=mmap.PROT_READ).__enter__()
        return self.m

    def __exit__(self, *args, **kwargs):
        self.m.__exit__(*args, **kwargs)
        self.f.__exit__(*args, **kwargs)


def show_info(fname):
    """
        Dump the informations contained in the structure
    """
    mupdate = PocketbookSwupdate.from_file(fname)

    print("Update magic: %s" % mupdate.header.magic)
    print("Update Model: %s" % mupdate.header.model)
    print("Update revision: %s" % mupdate.header.revision)
    print("Update md5 hash: %s" % binascii.hexlify(mupdate.header.md5_sum))
    print("Update signature: %s" % binascii.hexlify(mupdate.header.signature))

    print("Partition table:")
    for part in mupdate.header.fw_partitions:
        print("\toffset 0x%x size 0x%x type %s " % (
            part.offset,
            part.size,
            part.part_type,
            ))

    print("Checking hashes")
    check_md5(mupdate, fname)


def check_md5(update, fname):
    """
        Compute the checksum of the updates
        It creates a MD5 hash of the MD5 hashes of the partitions
    """
    mfile = open(fname, "rb")
    hashes = []
    for part in update.header.fw_partitions:
        mfile.seek(1024 + part.offset)
        data = mfile.read(part.size)
        hashes.append(md5(data).digest())

    mfile.close()

    final_hash = md5()
    for tmp in hashes[:-1]:
        final_hash.update(tmp)

    print("Header hash: %s" % (binascii.hexlify(update.header.md5_sum)))
    print("Calc   hash: %s" % (final_hash.hexdigest()))


def get_extension_from_type(part_type):
    """
        Outputs a sensible file extension given a partition type
    """
    extensions = {
        PocketbookSwupdate.PartTypeEnum.ebrmain_img: ".ebrmain",
        PocketbookSwupdate.PartTypeEnum.a_img: ".aimg",
        PocketbookSwupdate.PartTypeEnum.bmp_image: ".bmp",
        PocketbookSwupdate.PartTypeEnum.dragon_tar: "_dragon.tar",
        PocketbookSwupdate.PartTypeEnum.elf_megadog_img: "_megadog.elf",
        PocketbookSwupdate.PartTypeEnum.rootfs_img: ".rootfs",
        PocketbookSwupdate.PartTypeEnum.swupdate_tar_gz: "_swupdate.tar.gz",
        PocketbookSwupdate.PartTypeEnum.updatefs_cramfs: ".cramfs",
        PocketbookSwupdate.PartTypeEnum.uboot_loader: ".uboot",
        PocketbookSwupdate.PartTypeEnum.uboot_loader_too: ".uboot",
        PocketbookSwupdate.PartTypeEnum.kernel_img: ".kernel",
    }

    try:
        return extensions[part_type]
    except KeyError:
        return ".bin"


def dump(fname, namesByHash=True):
    """
        Dump the sections
    """
    
    with MMap(fname) as mfile:
        prefix = os.path.dirname(fname)
        mupdate = PocketbookSwupdate(KaitaiStream(mfile))
        for i, part in enumerate(mupdate.header.fw_partitions):
            if part.part_type != PocketbookSwupdate.PartTypeEnum.empty:
                print("Dumping section of type %s size 0x%x offset %x" % (
                    part.part_type,
                    part.size,
                    part.offset))
                mfile.seek(0)
                mfile.seek(part.offset + 1024)
                data = mfile.read(part.size + 8192)

                if namesByHash:
                    baseName = base64.b64encode(sha256(data).digest()).decode("ascii").replace("/", "@")
                else:
                    baseName = str(i)
                out = os.path.join(prefix, baseName + get_extension_from_type(part.part_type))

                with open(out, "wb") as out_file:
                    out_file.write(data)


def main():
    """
        Argument parsing and dispatching
    """
    actions = {
        "dump": lambda fn: dump(fn, True),
        "dump_no_hash": lambda fn: dump(fn, False),
        "info": show_info
    }
    parser = argparse.ArgumentParser("Test script for swupdate format parsing")
    parser.add_argument("action", choices=actions.keys())
    parser.add_argument("update", help="the update file")

    args = parser.parse_args()

    actions[args.action](args.update)


if __name__ == "__main__":
    main()
