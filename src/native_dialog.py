"""Native file dialogs (Qt/GTK on Linux, OS dialog on Windows), with a Tk fallback.

The app itself stays on Tk; only the picker is delegated to Qt so it matches the
platform's file chooser. Qt is optional: without PySide6 the old Tk dialogs are used.
"""
from pathlib import Path
import sys

_APP = None


def _app():
    global _APP
    if _APP is None:
        from PySide6.QtWidgets import QApplication
        _APP = QApplication.instance() or QApplication(sys.argv)
    return _APP


def _filter(filetypes):
    if not filetypes:
        return 'All Files (*)'
    patterns = []
    for label, pattern in filetypes:
        tokens = pattern.split() if isinstance(pattern, str) else [pattern]
        joined = ' '.join(tokens)
        patterns.append(f'{label} ({joined})')
    return ';;'.join(patterns)


def ask_open_file(title='Open', initialdir=None, filetypes=None, parent=None, **kw):
    try:
        from PySide6.QtWidgets import QFileDialog
        _app()
        result, _ = QFileDialog.getOpenFileName(None, title, str(initialdir or ''), _filter(filetypes))
        return result
    except ImportError:
        from tkinter import filedialog
        return filedialog.askopenfilename(title=title, initialdir=initialdir,
                                          filetypes=filetypes, parent=parent, **kw)


def ask_open_files(title='Open', initialdir=None, filetypes=None, parent=None, **kw):
    try:
        from PySide6.QtWidgets import QFileDialog
        _app()
        result, _ = QFileDialog.getOpenFileNames(None, title, str(initialdir or ''), _filter(filetypes))
        return tuple(result)
    except ImportError:
        from tkinter import filedialog
        return filedialog.askopenfilenames(title=title, initialdir=initialdir,
                                           filetypes=filetypes, parent=parent, **kw)


def ask_save_file(title='Save', initialdir=None, initialfile=None, defaultextension=None,
                  filetypes=None, parent=None, **kw):
    try:
        from PySide6.QtWidgets import QFileDialog
        _app()
        start = str(Path(initialdir) / initialfile) if initialdir and initialfile else (initialfile or initialdir or '')
        result, _ = QFileDialog.getSaveFileName(None, title, start, _filter(filetypes))
        if result and defaultextension:
            ext = defaultextension if defaultextension.startswith('.') else '.' + defaultextension
            if not result.lower().endswith(ext.lower()):
                result += ext
        return result
    except ImportError:
        from tkinter import filedialog
        return filedialog.asksaveasfilename(title=title, initialdir=initialdir, initialfile=initialfile,
                                            defaultextension=defaultextension, filetypes=filetypes,
                                            parent=parent, **kw)


def ask_directory(title='Choose folder', initialdir=None, parent=None, **kw):
    try:
        from PySide6.QtWidgets import QFileDialog
        _app()
        return QFileDialog.getExistingDirectory(None, title, str(initialdir or ''))
    except ImportError:
        from tkinter import filedialog
        return filedialog.askdirectory(title=title, initialdir=initialdir, parent=parent, **kw)
