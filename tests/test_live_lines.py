import io
import unittest

from spine.live_lines import OversizedLineError, read_complete_line


class LiveLineTests(unittest.TestCase):
    def test_partial_line_waits_then_completes(self):
        stream = io.BytesIO(b'{"event_type":"dns"')

        self.assertIsNone(read_complete_line(stream, 0))
        self.assertEqual(stream.tell(), 0)

        stream.seek(0, 2)
        stream.write(b"}\n")

        raw, next_offset = read_complete_line(stream, 0)
        self.assertEqual(raw, b'{"event_type":"dns"}\n')
        self.assertEqual(next_offset, len(raw))
        self.assertIsNone(read_complete_line(stream, next_offset))

    def test_split_utf8_is_not_decoded_prematurely(self):
        complete = '{"name":"café"}\n'.encode("utf-8")
        split = complete.index(b"\xc3") + 1
        stream = io.BytesIO(complete[:split])

        self.assertIsNone(read_complete_line(stream, 0))

        stream.seek(0, 2)
        stream.write(complete[split:])

        raw, next_offset = read_complete_line(stream, 0)
        self.assertEqual(raw.decode("utf-8"), '{"name":"café"}\n')
        self.assertEqual(next_offset, len(complete))

    def test_crlf_and_distinct_line_offsets_preserved(self):
        stream = io.BytesIO(b"{}\r\n{}\n")

        first, offset = read_complete_line(stream, 0)
        second, final_offset = read_complete_line(stream, offset)

        self.assertEqual(first, b"{}\r\n")
        self.assertEqual(offset, 4)
        self.assertEqual(second, b"{}\n")
        self.assertEqual(final_offset, 7)

    def test_oversized_line_does_not_advance(self):
        stream = io.BytesIO(b"123456789\n")

        with self.assertRaises(OversizedLineError):
            read_complete_line(stream, 0, max_line_bytes=8)

        self.assertEqual(stream.tell(), 0)


if __name__ == "__main__":
    unittest.main()