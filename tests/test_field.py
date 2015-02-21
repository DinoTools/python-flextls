import pytest

from flextls.exception import *
from flextls.field import *


class TestNumberFields(object):
    def test_uint8field(self):
        f = UInt8Field("test", 0)

        assert f.value == 0
        assert f.assemble() == b"\x00"

        f.value = 12
        assert f.value == 12
        assert f.assemble() == b"\x0c"

        f.dissect(b"\x00")
        assert f.value == 0

        assert f.dissect(b"\x0c") == b""
        assert f.value == 12

        assert f.dissect(b"\x0a\x99") == b"\x99"
        assert f.value == 10

        with pytest.raises(NotEnoughData):
            f.dissect(b"")

    def test_uint16field(self):
        f = UInt16Field("test", 0)

        assert f.value == 0
        assert f.assemble() == b"\x00\x00"

        f.value = 43788
        assert f.value == 43788
        assert f.assemble() == b"\xab\x0c"

        assert f.dissect(b"\x00\x00") == b""
        assert f.value == 0

        assert f.dissect(b"\xab\x0c") == b""
        assert f.value == 43788

        assert f.dissect(b"\x00\x00\x99") == b"\x99"
        assert f.value == 0

        with pytest.raises(NotEnoughData):
            f.dissect(b"")

        with pytest.raises(NotEnoughData):
            f.dissect(b"\x00")

    def test_uint24field(self):
        f = UInt24Field("test", 0)

        assert f.value == 0
        assert f.assemble() == b"\x00\x00\x00"

        f.value = 1193046
        assert f.value == 1193046
        assert f.assemble() == b"\x12\x34\x56"

        assert f.dissect(b"\x00\x00\x00") == b""
        assert f.value == 0

        assert f.dissect(b"\x12\x34\x56") == b""
        assert f.value == 1193046

        assert f.dissect(b"\x00\x00\x00\x99") == b"\x99"
        assert f.value == 0

        with pytest.raises(NotEnoughData):
            f.dissect(b"")

        with pytest.raises(NotEnoughData):
            f.dissect(b"\x12")

        with pytest.raises(NotEnoughData):
            f.dissect(b"\x12\x34")

    def test_uint48field(self):
        f = UInt48Field("test", 0)

        assert f.value == 0
        assert f.assemble() == b"\x00\x00\x00\x00\x00\x00"

        f.value = 20015998341291
        assert f.value == 20015998341291
        assert f.assemble() == b"\x12\x34\x56\x78\x90\xab"

        assert f.dissect(b"\x00\x00\x00\x00\x00\x00") == b""
        assert f.value == 0

        assert f.dissect(b"\x12\x34\x56\x78\x90\xab") == b""
        assert f.value == 20015998341291

        assert f.dissect(b"\x00\x00\x00\x00\x00\x00\x99") == b"\x99"
        assert f.value == 0

        with pytest.raises(NotEnoughData):
            f.dissect(b"")

        with pytest.raises(NotEnoughData):
            f.dissect(b"\x12")

        with pytest.raises(NotEnoughData):
            f.dissect(b"\x12\x34")

        with pytest.raises(NotEnoughData):
            f.dissect(b"\x12\x34\x56")

        with pytest.raises(NotEnoughData):
            f.dissect(b"\x12\x34\x56\x78")

        with pytest.raises(NotEnoughData):
            f.dissect(b"\x12\x34\x56\x78\x90")

    def test_randomfield(self):
        f = RandomField("test")

        assert f.value == b"A"*32
        assert f.assemble() == b"A"*32

        tmp1 = b"abcdefghijklmnopqrstuvwxyz123456"
        tmp2 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ098765"

        f.value = tmp1
        assert f.value == tmp1
        assert f.assemble() == tmp1

        assert f.dissect(tmp2) == b""
        assert f.value == tmp2

        assert f.dissect(tmp1 + tmp2) == tmp2

        for i in range(0, 32):
            with pytest.raises(NotEnoughData):
                f.dissect(b"A"*i)