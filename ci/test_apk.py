from struct import pack
import unittest

from verify_apk import verify_library


def library(alignment, address=0):
    ident = b"\x7fELF\x02\x01"
    return (
        pack("<16sHHIQQQIHHHHHH", ident, 3, 183, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        + pack("<IIQQQQQQ", 1, 5, 0, address, 0, 32, 32, alignment)
    )


class TestElf(unittest.TestCase):
    def test_aligned_load(self):
        verify_library(library(16384), "example.so")

    def test_rejects_four_kib_page_library(self):
        with self.assertRaisesRegex(ValueError, "16 KB"):
            verify_library(library(4096), "example.so")

    def test_rejects_wrong_segment_offset(self):
        with self.assertRaisesRegex(ValueError, "16 KB"):
            verify_library(library(16384, address=4096), "example.so")

    def test_rejects_truncated_segment_table(self):
        with self.assertRaisesRegex(ValueError, "program headers"):
            verify_library(library(16384)[:-1], "example.so")
