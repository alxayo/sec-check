"""
Progress tracking for AgentSec security scans.

This module provides the ProgressTracker class which tracks the state of
a security scan and emits progress updates. The CLI and GUI can subscribe
to these updates to show real-time progress information.

Usage:
    # Create a tracker with a callback
    def on_progress(event):
        print(f"[{event.type}] {event.message}")

    tracker = ProgressTracker(callback=on_progress)

    # Start tracking a scan
    tracker.start_scan(folder_path)

    # Update as files are discovered
    tracker.set_total_files(10)

    # Update as each file is scanned
    tracker.start_file("app.py")
    tracker.finish_file("app.py", issues_found=3)

    # Finish the scan
    tracker.finish_scan()
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional, List
from enum import Enum


class ProgressEventType(Enum):
    """
    Types of progress events that can be emitted during a scan.

    Each event type represents a different stage or action in the scanning
    process. The CLI/GUI can use these to display appropriate messages.
    """

    # Scan lifecycle events
    SCAN_STARTED = "scan_started"
    SCAN_FINISHED = "scan_finished"

    # File discovery events
    FILES_DISCOVERED = "files_discovered"

    # Individual file events
    FILE_STARTED = "file_started"
    FILE_FINISHED = "file_finished"

    # Periodic heartbeat to show the scan is still running
    HEARTBEAT = "heartbeat"

    # Error or warning during scan
    WARNING = "warning"
    ERROR = "error"


@dataclass
class ProgressEvent:
    """
    A single progress event emitted during a security scan.

    This dataclass holds all the information about a progress update.
    The callback function receives these events and can display them
    in whatever format is appropriate (CLI text, GUI progress bar, etc).

    Attributes:
        type: The type of event (see ProgressEventType enum)
        message: Human-readable description of what's happening
        current_file: Path to the file currently being processed (if any)
        files_scanned: Number of files scanned so far
        total_files: Total number of files to scan (0 if unknown)
        issues_found: Number of security issues found so far
        elapsed_seconds: Time elapsed since scan started
        percent_complete: Completion percentage (0-100), or -1 if unknown
    """

    type: ProgressEventType
    message: str
    current_file: Optional[str] = None
    files_scanned: int = 0
    total_files: int = 0
    issues_found: int = 0
    elapsed_seconds: float = 0.0
    percent_complete: float = -1.0


# Type alias for the progress callback function
ProgressCallback = Callable[[ProgressEvent], None]


class ProgressTracker:
    """
    Tracks the progress of a security scan and emits updates.

    This class is thread-safe and can be used from multiple async tasks.
    It maintains the current state of the scan (files scanned, time elapsed,
    etc.) and emits ProgressEvent objects through a callback function.

    The tracker also runs an optional heartbeat thread that emits periodic
    updates to show the scan is still running.

    Example:
        >>> def print_progress(event: ProgressEvent):
        ...     print(f"[{event.percent_complete:.0f}%] {event.message}")
        ...
        >>> tracker = ProgressTracker(callback=print_progress, heartbeat_interval=2.0)
        >>> tracker.start_scan("/path/to/project")
        >>> # ... scanning happens ...
        >>> tracker.finish_scan()
    """

    def __init__(
        self,
        callback: Optional[ProgressCallback] = None,
        heartbeat_interval: float = 5.0,
    ) -> None:
        """
        Initialize the progress tracker.

        Args:
            callback: Function to call when progress events occur.
                      If None, events are silently discarded.
            heartbeat_interval: Seconds between heartbeat events (0 to disable).
                                Default is 5 seconds.
        """
        self._callback = callback
        self._heartbeat_interval = heartbeat_interval

        # Scan state (protected by lock for thread safety)
        self._lock = threading.Lock()
        self._scan_active = False
        self._start_time: Optional[float] = None
        self._folder_path: Optional[str] = None
        self._current_file: Optional[str] = None
        self._files_scanned = 0
        self._total_files = 0
        self._issues_found = 0
        self._scanned_files: List[str] = []

        # Heartbeat thread
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._stop_heartbeat = threading.Event()

    def _emit(self, event: ProgressEvent) -> None:
        """
        Emit a progress event to the callback.

        This is a private method that sends events to the registered
        callback function. If no callback is set, events are discarded.

        Args:
            event: The progress event to emit
        """
        if self._callback:
            try:
                self._callback(event)
            except Exception:
                # Don't let callback errors crash the scan
                pass

    def _get_elapsed(self) -> float:
        """
        Get the elapsed time since the scan started.

        Returns:
            Elapsed time in seconds, or 0 if scan hasn't started
        """
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time

    def _get_percent(self) -> float:
        """
        Calculate the completion percentage.

        Returns:
            Percentage (0-100) if total is known, -1 if unknown
        """
        with self._lock:
            if self._total_files > 0:
                return (self._files_scanned / self._total_files) * 100.0
        return -1.0

    def _heartbeat_loop(self) -> None:
        """
        Background thread that emits periodic heartbeat events.

        This runs in a separate thread and emits HEARTBEAT events
        at regular intervals to show the scan is still active.
        """
        while not self._stop_heartbeat.wait(self._heartbeat_interval):
            with self._lock:
                if not self._scan_active:
                    break

                # Build heartbeat message
                elapsed = self._get_elapsed()
                minutes = int(elapsed // 60)
                seconds = int(elapsed % 60)

                if self._total_files > 0:
                    message = (
                        f"Scanning... {self._files_scanned}/{self._total_files} files, "
                        f"{self._issues_found} issues found ({minutes}m {seconds}s elapsed)"
                    )
                else:
                    message = (
                        f"Scanning... {self._files_scanned} files scanned, "
                        f"{self._issues_found} issues found ({minutes}m {seconds}s elapsed)"
                    )

                # Calculate percent directly here instead of calling
                # self._get_percent(), because _get_percent() also acquires
                # self._lock — and threading.Lock is NOT reentrant, so calling
                # it from inside a lock context would deadlock.
                if self._total_files > 0:
                    percent = (self._files_scanned / self._total_files) * 100.0
                else:
                    percent = -1.0

                event = ProgressEvent(
                    type=ProgressEventType.HEARTBEAT,
                    message=message,
                    current_file=self._current_file,
                    files_scanned=self._files_scanned,
                    total_files=self._total_files,
                    issues_found=self._issues_found,
                    elapsed_seconds=elapsed,
                    percent_complete=percent,
                )

            self._emit(event)

    def start_scan(self, folder_path: str) -> None:
        """
        Mark the start of a security scan.

        This resets all counters and starts the heartbeat thread.
        Call this at the beginning of a scan operation.

        Args:
            folder_path: The folder being scanned
        """
        with self._lock:
            self._scan_active = True
            self._start_time = time.time()
            self._folder_path = folder_path
            self._current_file = None
            self._files_scanned = 0
            self._total_files = 0
            self._issues_found = 0
            self._scanned_files = []

        # Start heartbeat thread if interval > 0
        if self._heartbeat_interval > 0:
            self._stop_heartbeat.clear()
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop,
                daemon=True,
            )
            self._heartbeat_thread.start()

        self._emit(ProgressEvent(
            type=ProgressEventType.SCAN_STARTED,
            message=f"Starting security scan of {folder_path}",
            elapsed_seconds=0.0,
        ))

    def set_total_files(self, total: int) -> None:
        """
        Set the total number of files to be scanned.

        This enables percentage calculation in progress updates.
        Call this after file discovery is complete.

        Args:
            total: Total number of files to scan
        """
        with self._lock:
            self._total_files = total

        self._emit(ProgressEvent(
            type=ProgressEventType.FILES_DISCOVERED,
            message=f"Found {total} files to scan",
            total_files=total,
            elapsed_seconds=self._get_elapsed(),
        ))

    def update_counts(
        self,
        files_scanned: Optional[int] = None,
        issues_found: Optional[int] = None,
    ) -> None:
        """
        Update the scan counters with corrected values.

        This is useful when the actual file and issue counts are determined
        after the scan completes (for example, by parsing the agent's final
        response). It allows the final progress summary to show accurate
        numbers instead of approximate tool-based counts.

        Args:
            files_scanned: If provided, overrides the files_scanned counter
            issues_found: If provided, overrides the issues_found counter
        """
        with self._lock:
            if files_scanned is not None:
                self._files_scanned = files_scanned
            if issues_found is not None:
                self._issues_found = issues_found

    def start_file(self, file_path: str) -> None:
        """
        Mark the start of scanning a specific file.

        Call this when beginning to analyze a new file.

        Args:
            file_path: Path to the file being scanned
        """
        with self._lock:
            self._current_file = file_path
            files_scanned = self._files_scanned
            total = self._total_files

        # Create a short display name for the file
        short_name = file_path.split("\\")[-1].split("/")[-1]

        if total > 0:
            message = f"Scanning ({files_scanned + 1}/{total}): {short_name}"
        else:
            message = f"Scanning: {short_name}"

        self._emit(ProgressEvent(
            type=ProgressEventType.FILE_STARTED,
            message=message,
            current_file=file_path,
            files_scanned=files_scanned,
            total_files=total,
            issues_found=self._issues_found,
            elapsed_seconds=self._get_elapsed(),
            percent_complete=self._get_percent(),
        ))

    def finish_file(self, file_path: str, issues_found: int = 0) -> None:
        """
        Mark the completion of scanning a specific file.

        Call this after a file has been analyzed. Updates the counters
        and emits a FILE_FINISHED event.

        Args:
            file_path: Path to the file that was scanned
            issues_found: Number of issues found in this file
        """
        with self._lock:
            self._files_scanned += 1
            self._issues_found += issues_found
            self._scanned_files.append(file_path)
            self._current_file = None

            files_scanned = self._files_scanned
            total = self._total_files
            total_issues = self._issues_found

        # Create a short display name for the file
        short_name = file_path.split("\\")[-1].split("/")[-1]

        if issues_found > 0:
            message = f"Finished {short_name}: {issues_found} issues found"
        else:
            message = f"Finished {short_name}: no issues"

        self._emit(ProgressEvent(
            type=ProgressEventType.FILE_FINISHED,
            message=message,
            current_file=file_path,
            files_scanned=files_scanned,
            total_files=total,
            issues_found=total_issues,
            elapsed_seconds=self._get_elapsed(),
            percent_complete=self._get_percent(),
        ))

    def emit_warning(self, message: str) -> None:
        """
        Emit a warning event during the scan.

        Use this for non-fatal issues like unreadable files.

        Args:
            message: Warning message to display
        """
        with self._lock:
            files_scanned = self._files_scanned
            total = self._total_files
            total_issues = self._issues_found

        self._emit(ProgressEvent(
            type=ProgressEventType.WARNING,
            message=message,
            files_scanned=files_scanned,
            total_files=total,
            issues_found=total_issues,
            elapsed_seconds=self._get_elapsed(),
            percent_complete=self._get_percent(),
        ))

    def emit_error(self, message: str) -> None:
        """
        Emit an error event during the scan.

        Use this for serious problems that may affect results.

        Args:
            message: Error message to display
        """
        with self._lock:
            files_scanned = self._files_scanned
            total = self._total_files
            total_issues = self._issues_found

        self._emit(ProgressEvent(
            type=ProgressEventType.ERROR,
            message=message,
            files_scanned=files_scanned,
            total_files=total,
            issues_found=total_issues,
            elapsed_seconds=self._get_elapsed(),
            percent_complete=self._get_percent(),
        ))

    def finish_scan(self) -> None:
        """
        Mark the completion of the security scan.

        This stops the heartbeat thread and emits a final summary.
        Call this at the end of a scan operation.
        """
        # Stop heartbeat thread
        if self._heartbeat_thread:
            self._stop_heartbeat.set()
            # Wait longer for thread to stop to avoid orphaned threads
            self._heartbeat_thread.join(timeout=3.0)
            self._heartbeat_thread = None

        with self._lock:
            self._scan_active = False
            elapsed = self._get_elapsed()
            files_scanned = self._files_scanned
            total_issues = self._issues_found

        # Format elapsed time nicely
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        if minutes > 0:
            time_str = f"{minutes}m {seconds}s"
        else:
            time_str = f"{seconds}s"

        self._emit(ProgressEvent(
            type=ProgressEventType.SCAN_FINISHED,
            message=f"Scan complete: {files_scanned} files scanned, {total_issues} issues found ({time_str})",
            files_scanned=files_scanned,
            total_files=files_scanned,
            issues_found=total_issues,
            elapsed_seconds=elapsed,
            percent_complete=100.0,
        ))

    def get_summary(self) -> dict:
        """
        Get a summary of the current scan state.

        This can be called at any time to get the current progress.

        Returns:
            Dictionary with scan statistics
        """
        with self._lock:
            # Calculate percent directly here instead of calling
            # self._get_percent(), because we already hold self._lock
            # and threading.Lock is NOT reentrant (would deadlock).
            if self._total_files > 0:
                percent = (self._files_scanned / self._total_files) * 100.0
            else:
                percent = -1.0

            return {
                "scan_active": self._scan_active,
                "folder_path": self._folder_path,
                "current_file": self._current_file,
                "files_scanned": self._files_scanned,
                "total_files": self._total_files,
                "issues_found": self._issues_found,
                "elapsed_seconds": self._get_elapsed(),
                "percent_complete": percent,
            }


# Global tracker instance that can be used across modules
# This allows skills to report progress without needing explicit references
_global_tracker: Optional[ProgressTracker] = None


def get_global_tracker() -> Optional[ProgressTracker]:
    """
    Get the global progress tracker instance.

    Returns:
        The global ProgressTracker, or None if not set
    """
    return _global_tracker


def set_global_tracker(tracker: Optional[ProgressTracker]) -> None:
    """
    Set the global progress tracker instance.

    This allows skills to access the tracker without explicit references.
    Call this before starting a scan if you want progress updates.

    Args:
        tracker: The ProgressTracker to use globally, or None to clear
    """
    global _global_tracker
    _global_tracker = tracker
