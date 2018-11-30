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
import binascii

from hashlib import md5, sha256

import swupdate

PREFIX = "./"


def show_info(fname):
    """
        Dump the informations contained in the structure
    """
    mupdate = swupdate.Swupdate.from_file(fname)

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
        swupdate.Swupdate.PartTypeEnum.ebrmain_img: ".ebrmain",
        swupdate.Swupdate.PartTypeEnum.a_img: ".aimg",
        swupdate.Swupdate.PartTypeEnum.bmp_image: ".bmp",
        swupdate.Swupdate.PartTypeEnum.dragon_tar: "_dragon.tar",
        swupdate.Swupdate.PartTypeEnum.elf_megadog_img: "_megadog.elf",
        swupdate.Swupdate.PartTypeEnum.rootfs_img: ".rootfs",
        swupdate.Swupdate.PartTypeEnum.swupdate_tar_gz: "_swupdate.tar.gz",
        swupdate.Swupdate.PartTypeEnum.updatefs_cramfs: ".cramfs",
        swupdate.Swupdate.PartTypeEnum.uboot_loader: ".uboot",
        swupdate.Swupdate.PartTypeEnum.kernel_img: ".kernel",
    }

    try:
        return extensions[part_type]
    except KeyError:
        return ".bin"


def dump(fname):
    """
        Dump the sections
    """
    mupdate = swupdate.Swupdate.from_file(fname)
    mfile = open(fname, "rb")

    for part in mupdate.header.fw_partitions:
        if part.part_type != swupdate.Swupdate.PartTypeEnum.empty:
            print("Dumping section of type %s size 0x%x offset %x" % (
                part.part_type,
                part.size,
                part.offset))
            mfile.seek(0)
            mfile.seek(part.offset + 1024)
            data = mfile.read(part.size + 8192)

            mhash = sha256(data).hexdigest()
            out = PREFIX + mhash
            out += get_extension_from_type(part.part_type)

            with open(out, "wb") as out_file:
                out_file.write(data)


def main():
    """
        Argument parsing and dispatching
    """
    actions = {
        "dump": dump,
        "info": show_info
    }
    parser = argparse.ArgumentParser("Test script for swupdate format parsing")
    parser.add_argument("action", choices=actions.keys())
    parser.add_argument("update", help="the update file")

    args = parser.parse_args()

    actions[args.action](args.update)


if __name__ == "__main__":
    main()
