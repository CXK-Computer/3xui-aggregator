# -*- coding: utf-8 -*-

import sys
import os
import csv
import threading
import traceback
import typing
from concurrent import futures

# --- PySide6 imports for GUI ---
from PySide6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                               QWidget, QLabel, QLineEdit, QPushButton, QFileDialog,
                               QSpinBox, QCheckBox, QTextEdit, QProgressBar, QGroupBox,
                               QFormLayout, QListWidget, QAbstractItemView, QDialog,
                               QDialogButtonBox, QMessageBox)
from PySide6.QtCore import QObject, QThread, Signal, Slot, Qt, QStandardPaths, QCoreApplication, QTranslator
from PySide6.QtGui import QAction, QIcon
# -------------------------------


# --- Custom Stream for redirecting stdout/stderr to GUI ---
class QTextEditLogger(QObject):
    message_written = Signal(str)

    def __init__(self, original_stream):
        super().__init__()
        self._original_stream = original_stream

    def write(self, text):
        # 只在文本非空且非纯空白时才发射信号
        if text and text.strip():
             self.message_written.emit(str(text))
        # 可选：保留向原始 stdout/stderr 写入的功能，方便调试
        try:
            if self._original_stream:
                self._original_stream.write(text)
                self._original_stream.flush()
        except Exception:
            pass # 避免日志系统本身的错误导致程序崩溃

    def flush(self):
        try:
            if self._original_stream:
                self._original_stream.flush()
        except Exception:
            pass
# --- End Custom Stream ---


# 将需要翻译的日志消息集中管理，使用 QCoreApplication.translate
def tr_log(context, text):
    """ Helper for translating non-QWidget/QObject strings """
    return QCoreApplication.translate(context, text)

# 帮助函数中的日志回调
def log_helper_message(log_callback: typing.Callable[[str], None], context: str, message: str):
     if log_callback:
         log_callback(tr_log(context, message))
     else:
         # Fallback to print if no callback is provided (e.g., console mode)
         print(tr_log(context, message))


# --- Worker Class for the Merging Logic ---
class MergeWorker(QObject):
    # Signals to communicate with the GUI
    finished = Signal()
    error = Signal(str)
    progress = Signal(int) # Percentage 0-100, represents files processed
    status_message = Signal(str) # Log messages from worker

    def __init__(self, config: dict):
        super().__init__()
        self.config = config
        self._is_canceled = False

    def cancel(self):
        self._is_canceled = True
        self.status_message.emit(self.tr("Cancellation requested."))

    def run(self):
        context = "MergeWorker" # Translation context
        input_files = self.config.get("input_files", [])
        output_path = self.config.get("output_path")
        output_delimiter = self.config.get("output_delimiter", ",") # Default to comma
        skip_headers = self.config.get("skip_headers", True)

        if not input_files:
            self.error.emit(self.tr("No input files selected."))
            self.finished.emit()
            return

        if not output_path:
            self.error.emit(self.tr("No output file specified."))
            self.finished.emit()
            return

        total_files = len(input_files)
        processed_files = 0
        first_file_processed = False

        self.status_message.emit(self.tr(f"Starting merge of {total_files} files to {output_path}..."))

        try:
            # Open the output file outside the loop
            # Use newline='' for csv writer to handle line endings correctly
            # Add encoding
            with open(output_path, 'w', newline='', encoding='utf-8') as outfile:
                # Use csv.writer to handle quoting and delimiters
                writer = csv.writer(outfile, delimiter=output_delimiter)

                for file_path in input_files:
                    if self._is_canceled:
                        self.status_message.emit(self.tr("Merge canceled."))
                        break # Exit file loop if canceled

                    processed_files += 1
                    current_progress = int((processed_files / total_files) * 100)
                    self.progress.emit(current_progress)
                    self.status_message.emit(self.tr(f"Processing file {processed_files}/{total_files}: {os.path.basename(file_path)}"))

                    try:
                        # Use 'r' mode for reading, encoding='utf-8'
                        # Error handling for file reading/decoding
                        with open(file_path, 'r', encoding='utf-8') as infile:
                            file_extension = os.path.splitext(file_path)[1].lower()

                            if file_extension == '.csv':
                                # Assume comma delimiter for input CSV
                                reader = csv.reader(infile, delimiter=',')
                                if skip_headers and not first_file_processed:
                                    try:
                                        next(reader) # Skip header row for the first file
                                        self.status_message.emit(self.tr(f"Skipping header for {os.path.basename(file_path)}"))
                                    except StopIteration:
                                        self.status_message.emit(self.tr(f"Warning: {os.path.basename(file_path)} is empty or has only a header."))
                                        pass # File is empty, nothing to read
                                first_file_processed = True

                                # Read remaining rows and write to output
                                for row in reader:
                                    writer.writerow(row)

                            elif file_extension == '.txt':
                                # For TXT files, treat each line as a single field in a row
                                # Skip header only if it's the very first file and skip_headers is true
                                if skip_headers and not first_file_processed:
                                     try:
                                        # Read the first line but don't process it as data
                                        line = next(infile)
                                        self.status_message.emit(self.tr(f"Skipping first line for {os.path.basename(file_path)}"))
                                     except StopIteration:
                                        self.status_message.emit(self.tr(f"Warning: {os.path.basename(file_path)} is empty."))
                                        pass # File is empty
                                first_file_processed = True # Mark first file processed regardless of type

                                for line in infile:
                                    line = line.strip() # Remove leading/trailing whitespace, including newline
                                    if line: # Only write non-empty lines
                                        writer.writerow([line]) # Write the whole line as a single field


                            else:
                                # Handle other file types if necessary, or just log a warning
                                self.status_message.emit(self.tr(f"Warning: Skipping unsupported file type: {os.path.basename(file_path)}"))
                                pass # Skip this file

                    except FileNotFoundError:
                        self.status_message.emit(self.tr(f"Error: Input file not found: {file_path}"))
                        # Continue with next file
                        continue
                    except UnicodeDecodeError:
                        self.status_message.emit(self.tr(f"Error: Could not decode file {os.path.basename(file_path)}. Ensure it is UTF-8 encoded."))
                        # Continue with next file
                        continue
                    except Exception as e:
                        self.status_message.emit(self.tr(f"Error processing file {os.path.basename(file_path)}: {e}"))
                        self.status_message.emit(traceback.format_exc())
                        # Continue with next file
                        continue

            # Ensure progress is 100% on successful completion
            if not self._is_canceled:
                self.progress.emit(100)
                self.status_message.emit(self.tr("Merge process completed successfully."))
            else:
                self.status_message.emit(self.tr("Merge process stopped by user."))


        except Exception as e:
            # Catch errors during output file handling or unexpected issues
            error_msg = self.tr(f"An unexpected error occurred during merge: {e}")
            log_traceback = traceback.format_exc()
            self.error.emit(error_msg) # Signal for message box
            self.status_message.emit(error_msg + "\n" + log_traceback) # Signal for log
            self.status_message.emit(self.tr("Merge failed due to an unexpected error."))
            self.progress.emit(0) # Reset progress on error

        finally:
            self.finished.emit() # Always emit finished signal


# --- GUI Main Window ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # Use self.tr() for window title
        self.setWindowTitle(self.tr("CSV/Text File Merger"))
        self.setGeometry(100, 100, 700, 500) # Adjust window size

        self.worker = None
        self.worker_thread = None
        self.input_files = [] # List to hold selected file paths

        # Store original streams before redirection
        self._original_stdout = sys.stdout
        self._original_stderr = sys.stderr

        self.setup_ui()
        self.connect_signals()

        # Redirect stdout/stderr to the QTextEdit log
        self.stdout_logger = QTextEditLogger(self._original_stdout)
        self.stdout_logger.message_written.connect(self.append_log)
        sys.stdout = self.stdout_logger

        self.stderr_logger = QTextEditLogger(self._original_stderr) # Use separate logger for stderr
        self.stderr_logger.message_written.connect(self.append_log)
        sys.stderr = self.stderr_logger


    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Input Files Group
        input_group = QGroupBox(self.tr("Input Files (CSV or TXT)"))
        input_layout = QVBoxLayout(input_group)

        self.fileListWidget = QListWidget()
        self.fileListWidget.setSelectionMode(QAbstractItemView.ExtendedSelection) # Allow selecting multiple items
        input_layout.addWidget(self.fileListWidget)

        file_buttons_layout = QHBoxLayout()
        self.addFilesButton = QPushButton(self.tr("Add Files..."))
        self.clearFilesButton = QPushButton(self.tr("Clear List"))
        file_buttons_layout.addWidget(self.addFilesButton)
        file_buttons_layout.addWidget(self.clearFilesButton)
        input_layout.addLayout(file_buttons_layout)

        main_layout.addWidget(input_group, 1) # Make file list expandable

        # Output Settings Group
        output_group = QGroupBox(self.tr("Output Settings"))
        output_layout = QFormLayout(output_group)

        self.outputPathEdit = QLineEdit()
        self.browseOutputButton = QPushButton(self.tr("Browse..."))
        output_path_layout = QHBoxLayout()
        output_path_layout.addWidget(self.outputPathEdit)
        output_path_layout.addWidget(self.browseOutputButton)
        output_layout.addRow(self.tr("Output File:"), output_path_layout)

        self.outputDelimiterEdit = QLineEdit(",") # Default to comma
        output_layout.addRow(self.tr("Output Delimiter:"), self.outputDelimiterEdit)

        self.skipHeadersCheckbox = QCheckBox(self.tr("Skip header row in input files (applies to the first file)"))
        self.skipHeadersCheckbox.setChecked(True) # Skip header by default
        output_layout.addRow("", self.skipHeadersCheckbox) # Add checkbox without label

        main_layout.addWidget(output_group)


        # Control Buttons
        control_layout = QHBoxLayout()
        self.startButton = QPushButton(self.tr("Start Merge"))
        self.cancelButton = QPushButton(self.tr("Cancel Merge"))
        self.cancelButton.setEnabled(False) # Disabled initially

        control_layout.addWidget(self.startButton)
        control_layout.addWidget(self.cancelButton)
        main_layout.addLayout(control_layout)

        # Progress Bar
        self.progressBar = QProgressBar()
        self.progressBar.setRange(0, 100)
        self.progressBar.setValue(0)
        main_layout.addWidget(self.progressBar)

        # Log Output
        log_group = QGroupBox(self.tr("Log Output"))
        log_layout = QVBoxLayout(log_group)
        self.logOutput = QTextEdit()
        self.logOutput.setReadOnly(True)
        log_layout.addWidget(self.logOutput)
        main_layout.addWidget(log_group, 1) # Stretch log area

        # Status Bar
        self.statusBar()

    def connect_signals(self):
        self.addFilesButton.clicked.connect(self.add_files)
        self.clearFilesButton.clicked.connect(self.clear_files)
        self.browseOutputButton.clicked.connect(self.browse_output_file)
        self.startButton.clicked.connect(self.start_merge)
        self.cancelButton.clicked.connect(self.cancel_merge)

    @Slot()
    def add_files(self):
        # Use self.tr() for dialog title and filters
        filenames, _ = QFileDialog.getOpenFileNames(self, self.tr("Select Input Files"), "", self.tr("Data Files (*.csv *.txt);;CSV Files (*.csv);;Text Files (*.txt);;All Files (*)"))
        if filenames:
            added_count = 0
            for fname in filenames:
                # Avoid adding duplicates
                if fname not in self.input_files:
                    self.input_files.append(fname)
                    self.fileListWidget.addItem(os.path.basename(fname)) # Display only filename in list
                    added_count += 1
            if added_count > 0:
                self.append_log(self.tr(f"Added {added_count} file(s). Total: {len(self.input_files)}"))


    @Slot()
    def clear_files(self):
        self.input_files = []
        self.fileListWidget.clear()
        self.append_log(self.tr("Input file list cleared."))


    @Slot()
    def browse_output_file(self):
        # Use self.tr() for dialog title and filters
        filename, _ = QFileDialog.getSaveFileName(self, self.tr("Save Merged File As"), "", self.tr("CSV Files (*.csv);;Text Files (*.txt);;All Files (*)"))
        if filename:
            self.outputPathEdit.setText(filename)

    @Slot()
    def start_merge(self):
        # Validate inputs
        if not self.input_files:
            QMessageBox.warning(self, self.tr("Input Error"), self.tr("Please add input files first."))
            return

        output_path = self.outputPathEdit.text().strip()
        if not output_path:
            QMessageBox.warning(self, self.tr("Input Error"), self.tr("Please specify an output file."))
            return

        output_delimiter = self.outputDelimiterEdit.text()
        if not output_delimiter:
             QMessageBox.warning(self, self.tr("Input Error"), self.tr("Please specify an output delimiter."))
             return
        if len(output_delimiter) > 1:
             reply = QMessageBox.question(self, self.tr("Warning"), self.tr("The output delimiter is more than one character. Is this intentional?"),
                                          QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
             if reply == QMessageBox.No:
                  return


        # Disable buttons and clear log/progress
        self.startButton.setEnabled(False)
        self.cancelButton.setEnabled(True)
        self.logOutput.clear()
        self.progressBar.setValue(0)
        self.statusBar().clearMessage()

        # Get configuration from UI
        config = {
            "input_files": self.input_files,
            "output_path": output_path,
            "output_delimiter": output_delimiter,
            "skip_headers": self.skipHeadersCheckbox.isChecked(),
        }

        # Create and start the worker thread
        self.worker_thread = QThread()
        self.worker = MergeWorker(config)
        self.worker.moveToThread(self.worker_thread)

        # Connect worker signals to GUI slots
        self.worker_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.finished.connect(self.worker_thread.deleteLater)
        self.worker.finished.connect(self.merge_finished) # Custom slot for cleanup

        self.worker.error.connect(self.handle_error)
        self.worker.progress.connect(self.progressBar.setValue)
        self.worker.status_message.connect(self.append_log)

        # Start the thread
        self.worker_thread.start()
        self.statusBar().showMessage(self.tr("Merge started..."))
        # append_log is called by worker's status_message signal now

    @Slot()
    def cancel_merge(self):
        if self.worker and self.worker_thread and self.worker_thread.isRunning():
            self.worker.cancel()
            self.statusBar().showMessage(self.tr("Canceling merge..."))
            # The worker's run method checks the cancel flag and will exit its loops

    @Slot()
    def merge_finished(self):
        # This slot is connected to the worker's finished signal
        # The worker sends a final status message before finishing
        self.statusBar().showMessage(self.tr("Merge finished."))
        self.reset_ui() # Re-enable buttons etc.

    @Slot(str)
    def handle_error(self, error_message):
        # Use self.tr() for QMessageBox title
        QMessageBox.critical(self, self.tr("Merge Error"), error_message)
        # Error message text is already translated by the worker if it uses self.tr() or tr_log()
        # self.append_log(self.tr("ERROR: ") + error_message) # Log is already appended by worker
        self.reset_ui() # Ensure UI is reset on error

    @Slot(str)
    def append_log(self, text):
        # Ensure appending happens on the GUI thread
        if self.logOutput:
             # Add a newline if the text doesn't end with one and isn't just whitespace
             if text and not text.endswith('\n') and text.strip():
                  text += '\n'
             self.logOutput.insertPlainText(text)
             self.logOutput.verticalScrollBar().setValue(self.logOutput.verticalScrollBar().maximum()) # Auto-scroll

    def reset_ui(self):
        # Reset button states
        self.startButton.setEnabled(True)
        self.cancelButton.setEnabled(False)
        # Clean up worker and thread objects
        self.worker = None
        self.worker_thread = None
        # Progress bar might stay at 100% or reset depending on preference, let's keep 100% on success/finish

    def closeEvent(self, event):
        # Handle window closing: check if thread is running and ask user
        if self.worker_thread and self.worker_thread.isRunning():
            # Use self.tr() for QMessageBox titles and text
            reply = QMessageBox.question(self, self.tr("Merge in Progress"),
                                         self.tr("A merge is currently running. Do you want to cancel it and exit?"),
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.cancel_merge()
                # Wait a bit for the thread to stop gracefully
                if not self.worker_thread.wait(2000): # Wait up to 2 seconds
                    self.worker_thread.terminate() # Force terminate if it doesn't stop
                    self.worker_thread.wait(500) # Wait a bit more after terminate
                # Restore original stdout/stderr before exiting
                sys.stdout = self._original_stdout
                sys.stderr = self._original_stderr
                event.accept() # Close the window
            else:
                event.ignore() # Don't close the window
        else:
            # Restore original stdout/stderr before exiting
            sys.stdout = self._original_stdout
            sys.stderr = self._original_stderr
            event.accept() # Close the window

if __name__ == "__main__":
    app = QApplication(sys.argv)

    # --- Load Translator (for Chinese simplified) ---
    # Assumes you have zh_CN.qm file in the same directory as the script
    # For deployment, you might place this in a 'translations' subdirectory
    translator = QTranslator()
    # Try loading the translation file. The name 'zh_CN' matches locale code.
    # If the file is in a subdirectory like 'translations', use `translator.load("zh_CN", "translations")`
    # You might want to try multiple paths or locale names
    translations_path = os.path.join(os.path.dirname(__file__), 'translations') # Example subdirectory
    if translator.load("zh_CN", translations_path) or translator.load("zh_CN", os.path.dirname(__file__)):
         app.installTranslator(translator)
         print("Loaded Chinese translation.")
    else:
         print("Failed to load Chinese translation (zh_CN.qm not found or invalid). Using default language.")
    # --- End Load Translator ---

    main_window = MainWindow()
    main_window.show()

    sys.exit(app.exec())