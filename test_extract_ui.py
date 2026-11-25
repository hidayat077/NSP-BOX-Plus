"""UI checks for the NSP extract/convert panel."""
from pathlib import Path
import sys, tempfile, time, unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).parent / 'src'))
from app import App
from extract_panel import MODES


class ExtractInterfaceTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).parent / 'test-work'
        scratch.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=scratch)
        self.root = Path(self.tmp.name)
        self.app = App(show_startup=False, preferences_path=self.root / 'prefs.json')
        self.errors = []
        self.app.report_callback_exception = lambda *a: self.errors.append(a)
        self.app.show_tab('extract')
        self.pump(.3)

    def tearDown(self):
        self.app.close()
        self.tmp.cleanup()

    def pump(self, seconds=.04):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.app.update()
            time.sleep(.005)

    def test_custom_output_folder_is_not_reset_by_source_or_mode_changes(self):
        p = self.app.extract_panel
        source = self.root / 'Game.nsp'
        source.write_bytes(b'x')
        p.input.set(str(source))
        self.pump()
        chosen = self.root / 'Elsewhere'
        chosen.mkdir()
        with patch('extract_panel.native_dialog.ask_directory', return_value=str(chosen)):
            p.pick_output()
        self.assertEqual(p.output.get(), str(chosen / 'Game-extracted'))

        other = self.root / 'Other.nsp'
        other.write_bytes(b'x')
        p.input.set(str(other))
        self.pump()
        self.assertEqual(p.output.get(), str(chosen / 'Other-extracted'))

        p.mode.set(MODES[1])
        self.pump()
        self.assertEqual(p.output.get(), str(chosen / 'Other.nup'))
        self.assertFalse(self.errors)


if __name__ == '__main__':
    unittest.main()
