import unittest

from spine.pipeline import normalize_record


SAMPLE = r"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Sysmon"/>
<EventID>1</EventID>
<Level>4</Level>
<TimeCreated SystemTime="2026-10-03T18:04:22.7845238Z"/>
<EventRecordID>31451</EventRecordID>
<Execution ProcessID="4912" ThreadID="6052"/>
<Channel>Microsoft-Windows-Sysmon/Operational</Channel>
<Computer>TEST-HOST</Computer>
</System>
<EventData>
<Data Name="UtcTime">2026-10-03 18:04:22.782</Data>
<Data Name="ProcessId">5820</Data>
<Data Name="Image">C:\Windows\System32\taskhostw.exe</Data>
<Data Name="ParentProcessId">2056</Data>
<Data Name="CommandLine">tool.exe &amp; argument</Data>
<Data Name="ExtraField">preserve me</Data>
</EventData>
</Event>"""


class SysmonXmlTests(unittest.TestCase):
    def parse(self, text=SAMPLE, identity="fixture:generation-1:31451"):
        return normalize_record(
            text,
            input_format="sysmon_xml",
            source_scope="lab/windows-sysmon",
            source_record_id=identity,
            observed_time="2026-10-03T18:05:00Z",
        )

    def test_process_mapping_and_telemetry(self):
        record = self.parse()

        self.assertEqual(record["collector"], "sysmon_eventlog")
        self.assertEqual(record["record_kind"], "telemetry")
        self.assertEqual(record["event"]["type"], "process_create")
        self.assertEqual(record["attributes"]["process"]["id"], 5820)
        self.assertEqual(
            record["attributes"]["windows_system"]["execution_process_id"],
            4912,
        )
        self.assertIsNone(record["priority"]["wazuh_level"])
        self.assertIsNone(record["priority"]["priority_band"])
        self.assertFalse(
            any(item["type"] == "alert" for item in record["entities"])
        )

    def test_raw_paths_and_unknown_fields_preserved(self):
        record = self.parse()

        self.assertEqual(record["raw"]["text"], SAMPLE)
        self.assertEqual(
            record["attributes"]["process"]["image"],
            r"C:\Windows\System32\taskhostw.exe",
        )
        self.assertEqual(
            record["attributes"]["process"]["command_line"],
            "tool.exe & argument",
        )
        self.assertEqual(
            record["attributes"]["source_payload"]
            ["eventdata_original"]["ExtraField"],
            "preserve me",
        )

    def test_both_timestamp_precisions_preserved(self):
        record = self.parse()

        self.assertEqual(
            record["event_time"]["utc"],
            "2026-10-03T18:04:22.782Z",
        )
        self.assertEqual(
            record["attributes"]["windows_system"]["time_created"]["utc"],
            "2026-10-03T18:04:22.7845238Z",
        )

    def test_other_event_id_is_not_process_creation(self):
        record = self.parse(
            SAMPLE.replace("<EventID>1</EventID>", "<EventID>5</EventID>")
        )
        self.assertNotIn("process", record["attributes"])
        self.assertNotEqual(record["event"].get("type"), "process_create")
        self.assertIn(
            "ExtraField",
            record["attributes"]["source_payload"]["eventdata_original"],
        )

    def test_ambiguous_or_unsafe_xml_rejected(self):
        invalid_samples = [
            "<!DOCTYPE Event>" + SAMPLE,
            SAMPLE.replace(
                "</EventData>",
                '<Data Name="ProcessId">99</Data></EventData>',
            ),
            SAMPLE.replace(
                "<EventID>1</EventID>",
                "<EventID>1</EventID><EventID>5</EventID>",
            ),
            SAMPLE.replace(
                'Name="Microsoft-Windows-Sysmon"',
                'Name="Another-Provider"',
            ),
        ]
        for text in invalid_samples:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    self.parse(text)

    def test_reader_generation_controls_identity(self):
        first = self.parse()
        replay = self.parse()
        other_generation = self.parse(
            identity="fixture:generation-2:31451"
        )

        self.assertEqual(first["record_id"], replay["record_id"])
        self.assertNotEqual(
            first["record_id"], other_generation["record_id"]
        )


if __name__ == "__main__":
    unittest.main()