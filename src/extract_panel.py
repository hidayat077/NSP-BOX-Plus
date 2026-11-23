"""Extract encrypted NSP/XCI dumps into editable folders. Workers never call Tk."""
from pathlib import Path
import os, queue, subprocess, sys, threading, time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import native_dialog
import nsp_extract
from ui import BG, PANEL, TEXT, MUTED, Button, Entry, Check, Panel, Progress, ui_font, AmbientFrame, AmbientLabel


MODES = ('Extract to folder', 'Convert to .NUP', 'Convert to .NSP')


def automatic_output(source, parent=None, mode=MODES[0]):
    value = Path(source).absolute()
    stem = value.stem
    folder = Path(parent).absolute() if parent else value.parent
    suffix = '.nup' if mode == MODES[1] else ('.nsp' if mode == MODES[2] else '-extracted')
    candidate = folder / (stem + suffix)
    number = 2
    while candidate.exists():
        candidate = folder / (f'{stem} ({number})' + suffix)
        number += 1
    return str(candidate)


class ExtractPanel(AmbientFrame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self.app = parent
        self.events = queue.Queue()
        self.cancel_event = threading.Event()
        self.busy = False
        self.last_output = None
        self.controls = []
        self.input = tk.StringVar(self)
        self.update_path = tk.StringVar(self)
        self.dlc_paths = tk.StringVar(self)
        self.prod_keys = tk.StringVar(self, value=str(nsp_extract.default_keys() or ''))
        self.title_keys = tk.StringVar(self)
        self.output = tk.StringVar(self)
        self.status = tk.StringVar(self, value='Choose a base NSP to begin.')
        self._last_stage = None
        self._last_log_time = 0.0
        self._progress_value = 0.0
        self.includes = {name: tk.BooleanVar(self, value=True)
                         for name in ('ExeFS', 'RomFS', 'Control', 'DLC')}
        self.mode = tk.StringVar(self, value=MODES[0])
        self._layout()
        self.input.trace_add('write', self.changed)
        self.job = self.after(90, self.poll)

    def label(self, parent, text=None, variable=None, color=MUTED, size=9, **kw):
        cls = AmbientLabel if isinstance(parent, AmbientFrame) else tk.Label
        return cls(parent, text=text, textvariable=variable, bg=parent.cget('bg'), fg=color, font=ui_font(size), **kw)

    def append_log(self, text):
        self.log.configure(state='normal')
        self.log.insert('end', text + '\n')
        self.log.see('end')
        self.log.configure(state='disabled')

    def _field(self, parent, variable, placeholder, title, kind='file'):
        row = tk.Frame(parent, bg=PANEL)
        row.pack(fill='x', pady=(0, 8))
        entry = Entry(row, textvariable=variable, placeholder=placeholder)
        entry.pack(side='left', fill='x', expand=True)
        button = Button(row, '', lambda: self.pick(variable, title), self.app.motion,
                        width=36, height=36, kind=kind)
        button.pack(side='right', padx=(6, 0))
        self.controls.extend((entry, button))
        return row

    def _layout(self):
        area = AmbientFrame(self)
        area.pack(fill='both', expand=True, padx=20, pady=(0, 12))
        area.grid_columnconfigure(0, weight=1)
        area.grid_columnconfigure(1, minsize=320)
        area.grid_rowconfigure(0, weight=1)
        source = Panel(area, fluid_resize=True)
        source.grid(row=0, column=0, sticky='nsew', padx=(0, 12))
        self.app.heading(source.inner, 'NSP source', 'game-files')
        self.label(source.inner, 'Base NSP / XCI (your own dump)').pack(anchor='w', pady=(0, 5))
        self._field(source.inner, self.input, 'Base game package', 'Choose the base NSP')
        self.label(source.inner, 'Optional update NSP (merged on top)').pack(anchor='w', pady=(4, 5))
        self._field(source.inner, self.update_path, 'Update package', 'Choose the update NSP')
        self.label(source.inner, 'Optional DLC NSPs (comma separated)').pack(anchor='w', pady=(4, 5))
        self._field(source.inner, self.dlc_paths, 'DLC packages', 'Choose a DLC NSP')
        self.app.heading(source.inner, 'Your keys', 'save-output')
        self.label(source.inner, 'prod.keys is required for encrypted games; title.keys or tickets are used for titlekey content.',
                   wraplength=420, justify='left').pack(anchor='w', pady=(0, 8))
        self._field(source.inner, self.prod_keys, 'Path to prod.keys', 'Choose prod.keys')
        self._field(source.inner, self.title_keys, 'Optional title.keys', 'Choose title.keys')

        options = Panel(area)
        options.grid(row=0, column=1, sticky='nsew')
        self.app.heading(options.inner, 'Extract', 'package-folder')
        self.include_controls = []
        for name, var in self.includes.items():
            control = Check(options.inner, name, var)
            control.pack(anchor='w', fill='x', pady=(0, 4))
            self.include_controls.append(control)
        self.controls.extend(self.include_controls)
        self.mode_box = ttk.Combobox(options.inner, textvariable=self.mode, values=MODES, state='readonly')
        self.mode_box.pack(anchor='w', fill='x', pady=(6, 0))
        self.controls.append(self.mode_box)
        self.mode.trace_add('write', self.mode_changed)
        self.label(options.inner, 'Output', color=TEXT, size=10).pack(anchor='w', pady=(14, 5))
        out_row = tk.Frame(options.inner, bg=PANEL)
        out_row.pack(fill='x')
        self.output_entry = Entry(out_row, textvariable=self.output, placeholder='Automatic · beside source')
        self.output_entry.pack(side='left', fill='x', expand=True)
        self.output_button = Button(out_row, '', self.pick_output, self.app.motion,
                                    width=36, height=36, kind='browse-folder')
        self.output_button.pack(side='right', padx=(4, 0))
        self.controls.extend((self.output_entry, self.output_button))
        self.label(options.inner,
                   'Extracts into <TitleID>/exefs, romfs, control and dlc — the same layout the Game and DLC tabs accept. '
                   'No source file is modified. Plaintext (emulator) NSPs need no keys.',
                   wraplength=300, justify='left').pack(anchor='w', pady=(10, 0))
        self.label(options.inner, 'Activity log', color=TEXT, size=10).pack(anchor='w', pady=(12, 5))
        log_row = tk.Frame(options.inner, bg=PANEL)
        log_row.pack(fill='both', expand=True)
        self.log = tk.Text(log_row, bg=PANEL, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0,
                           highlightthickness=0, font=ui_font(9), wrap='word', height=6, state='disabled')
        scroll = ttk.Scrollbar(log_row, command=self.log.yview)
        scroll.pack(side='right', fill='y')
        self.log.configure(yscrollcommand=scroll.set)
        self.log.pack(side='left', fill='both', expand=True)
        self.panels = [source, options]

        self.progress = Progress(self, self.app.motion)
        self.progress.pack(fill='x')
        footer = AmbientFrame(self)
        footer.pack(fill='x', padx=24, pady=(12, 18))
        self.status_label = self.label(footer, variable=self.status, wraplength=380, justify='left')
        self.status_label.pack(side='left', fill='x', expand=True)
        self.start_button = Button(footer, 'Extract', self.start, self.app.motion,
                                   width=140, height=47, primary=True, kind='build')
        self.start_button.pack(side='right', padx=(10, 0))
        self.cancel_button = Button(footer, 'Cancel', self.cancel, self.app.motion,
                                    width=100, height=47, kind='cancel', state='disabled')
        self.cancel_button.pack(side='right', padx=(10, 0))
        self.open_button = Button(footer, 'Open output', self.open_output, self.app.motion,
                                  width=140, height=47, kind='open-output', state='disabled')
        self.open_button.pack(side='right', padx=(10, 0))

    def pick(self, variable, title, multiple=False):
        if self.busy:
            return
        if multiple:
            value = native_dialog.ask_open_files(parent=self.app, title=title, filetypes=[('NSP packages', '*.nsp')])
            if value:
                variable.set(', '.join(value))
        else:
            value = native_dialog.ask_open_file(parent=self.app, title=title,
                                               filetypes=[('Packages and key files', '*.nsp *.nsz *.xci *.ncz *.keys')])
            if value:
                variable.set(value)

    def pick_output(self):
        if self.busy:
            return
        current = Path(self.output.get()).parent if self.output.get() else None
        folder = native_dialog.ask_directory(parent=self.app, title='Choose output folder or disk',
                                         initialdir=str(current) if current else None)
        if folder:
            self.output.set(automatic_output(self.input.get() or 'game', folder, self.mode.get()))

    def mode_changed(self, *args):
        self.changed()

    def changed(self, *args):
        if self.busy:
            return
        value = self.input.get().strip()
        mode = self.mode.get()
        self.output.set(automatic_output(value, mode=mode) if value else '')
        self.status.set('Ready.' if value else 'Choose a base NSP to begin.')

    def set_busy(self, value):
        self.busy = value
        for control in self.controls + [self.start_button]:
            control.configure(state='disabled' if value else 'normal')
        self.cancel_button.configure(state='normal' if value else 'disabled')

    def start(self):
        if self.busy:
            return
        source = self.input.get().strip()
        if not source:
            self.status.set('Choose a base NSP first.')
            return
        if not Path(source).is_file():
            self.status.set('That base NSP does not exist.')
            return
        if not (self.includes['ExeFS'].get() or self.includes['RomFS'].get() or
                self.includes['Control'].get() or self.includes['DLC'].get()):
            self.status.set('Select at least one content type.')
            return
        mode = self.mode.get()
        output = self.output.get().strip() or automatic_output(source, mode=mode)
        expected = {MODES[1]: '.nup', MODES[2]: '.nsp'}.get(mode)
        if expected and Path(output).suffix.lower() != expected:
            self.status.set(f'Output must end in {expected}.')
            return
        if Path(output).exists():
            self.status.set('Choose a new output; existing files are never overwritten.')
            return
        dlc = [p.strip() for p in self.dlc_paths.get().split(',') if p.strip()]
        prod = self.prod_keys.get().strip() or None
        title = self.title_keys.get().strip() or None
        update = self.update_path.get().strip() or None
        includes = dict(self.includes)
        self.set_busy(True)
        self.cancel_event.clear()
        self.progress['value'] = 0
        self._progress_value = 0.0
        self.status.set('Preparing extraction…' if mode == MODES[0] else 'Preparing conversion…')
        self.log.configure(state='normal')
        self.log.delete('1.0', 'end')
        self.log.configure(state='disabled')
        self._last_stage = None
        self._last_log_time = 0.0
        self.append_log(f'Base: {source}')
        if update:
            self.append_log(f'Update: {update}')
        if dlc:
            self.append_log(f'DLC: {len(dlc)} file(s)')
        self.append_log(f'Output: {output}')
        last = [0]

        def notify(stage, value):
            now = time.monotonic()
            if now - last[0] > .1 or value >= 100:
                last[0] = now
                self.events.put(('progress', (stage, value)))

        def run():
            try:
                options = dict(prod_keys=prod, title_keys=title, update=update, dlc=dlc,
                               exefs=includes['ExeFS'].get(), romfs=includes['RomFS'].get(),
                               control=includes['Control'].get(), dlc_romfs=includes['DLC'].get(),
                               notify=notify, cancel=self.cancel_event)
                if mode == MODES[2]:
                    result = nsp_extract.nsp_to_nsp(source, output, prod, title, update,
                                                    notify=notify, cancel=self.cancel_event)
                elif mode == MODES[1]:
                    result = nsp_extract.nsp_to_nup(source, output, **options)
                else:
                    result = nsp_extract.extract(source, output, **options)
                self.events.put(('done', result))
            except InterruptedError:
                self.events.put(('cancelled', None))
            except Exception as error:
                self.events.put(('error', str(error)))

        threading.Thread(target=run, daemon=True).start()

    def poll(self):
        try:
            while True:
                kind, data = self.events.get_nowait()
                if kind == 'progress':
                    stage, value = data
                    self._progress_value = max(self._progress_value, value)
                    self.progress['value'] = self._progress_value
                    if not self.cancel_event.is_set():
                        self.status.set(f'{stage} · {value:.0f}%')
                    headline = stage.split(' · ', 1)[0]
                    now = time.monotonic()
                    if headline != self._last_stage or now - self._last_log_time > 1.0:
                        self._last_stage = headline
                        self._last_log_time = now
                        self.append_log(f'{stage} · {value:.0f}%')
                elif kind == 'done':
                    self.set_busy(False)
                    self.progress['value'] = 100
                    self.last_output = Path(data['output'])
                    self.open_button.configure(state='normal')
                    if 'files' in data:
                        self.status.set(f'Extracted {data["files"]:,} files · {data["title_id"]}')
                        self.append_log(f'Done · {data["files"]:,} files, {data["size"] / 1e9:.2f} GB · {data["title_id"]}')
                    else:
                        kind = 'NSP' if self.last_output.suffix.lower() == '.nsp' else 'NUP'
                        self.status.set(f'{kind} ready · {data["size"] / 1e9:.2f} GB')
                        self.append_log(f'Done · {kind} · {data["size"] / 1e9:.2f} GB · {data.get("title_id", "")}')
                    for warning in data.get('warnings', []):
                        self.append_log('Warning: ' + warning)
                elif kind == 'cancelled':
                    self.set_busy(False)
                    self.status.set('Cancelled · unfinished output removed; sources unchanged.')
                    self.append_log('Cancelled · unfinished output removed.')
                elif kind == 'error':
                    self.set_busy(False)
                    self.status.set(data)
                    self.append_log('Error: ' + data)
                    messagebox.showerror('Extraction failed', data, parent=self.app)
        except queue.Empty:
            pass
        self.job = self.after(90, self.poll)

    def cancel(self):
        self.cancel_event.set()
        self.cancel_button.configure(state='disabled')
        self.status.set('Cancelling and cleaning up…')

    def open_output(self):
        if not self.last_output:
            return
        try:
            target = self.last_output if self.last_output.is_dir() else self.last_output.parent
            if sys.platform == 'win32':
                os.startfile(str(target))
            else:
                subprocess.Popen(['xdg-open', str(target)])
        except OSError as error:
            self.status.set(str(error))

    def close(self):
        if self.busy:
            self.cancel()
            return False
        if self.job:
            self.after_cancel(self.job)
            self.job = None
        return True
