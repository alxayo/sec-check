"""
Tests for the progress tracking module.

This file tests the ProgressTracker class to ensure it correctly
tracks and emits progress events during a security scan.
"""

import sys
import os
import time

# Add the core package to the path for testing
# This allows running the test directly without pip install
core_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, core_path)

from agentsec.progress import (
    ProgressTracker,
    ProgressEvent,
    ProgressEventType,
    get_global_tracker,
    set_global_tracker,
)


def test_progress_tracker_basic():
    """
    Test basic progress tracker functionality.
    
    This test verifies that the progress tracker:
    1. Emits SCAN_STARTED event when starting a scan
    2. Emits FILES_DISCOVERED event when setting total files
    3. Emits FILE_STARTED and FILE_FINISHED events for each file
    4. Emits SCAN_FINISHED event when completing the scan
    """
    # Collect all events that are emitted
    events_received = []
    
    def callback(event: ProgressEvent):
        events_received.append(event)
    
    # Create a tracker with no heartbeat (for simpler testing)
    tracker = ProgressTracker(callback=callback, heartbeat_interval=0)
    
    # Start a scan
    tracker.start_scan("/test/folder")
    
    # Set total files
    tracker.set_total_files(3)
    
    # Simulate scanning 3 files
    tracker.start_file("/test/folder/file1.py")
    tracker.finish_file("/test/folder/file1.py", issues_found=0)
    
    tracker.start_file("/test/folder/file2.py")
    tracker.finish_file("/test/folder/file2.py", issues_found=2)
    
    tracker.start_file("/test/folder/file3.py")
    tracker.finish_file("/test/folder/file3.py", issues_found=1)
    
    # Finish the scan
    tracker.finish_scan()
    
    # Verify events
    event_types = [e.type for e in events_received]
    
    assert ProgressEventType.SCAN_STARTED in event_types, "SCAN_STARTED event missing"
    assert ProgressEventType.FILES_DISCOVERED in event_types, "FILES_DISCOVERED event missing"
    assert event_types.count(ProgressEventType.FILE_STARTED) == 3, "Should have 3 FILE_STARTED events"
    assert event_types.count(ProgressEventType.FILE_FINISHED) == 3, "Should have 3 FILE_FINISHED events"
    assert ProgressEventType.SCAN_FINISHED in event_types, "SCAN_FINISHED event missing"
    
    # Verify the final summary
    summary = tracker.get_summary()
    assert summary["files_scanned"] == 3, f"Expected 3 files scanned, got {summary['files_scanned']}"
    assert summary["issues_found"] == 3, f"Expected 3 issues, got {summary['issues_found']}"
    
    print("✅ test_progress_tracker_basic passed!")


def test_progress_tracker_percentage():
    """
    Test that percentage calculation works correctly.
    
    When total_files is set, the tracker should calculate
    the correct completion percentage.
    """
    events_received = []
    
    def callback(event: ProgressEvent):
        events_received.append(event)
    
    tracker = ProgressTracker(callback=callback, heartbeat_interval=0)
    
    tracker.start_scan("/test")
    tracker.set_total_files(4)
    
    # After processing 2 of 4 files, should be 50%
    tracker.start_file("file1.py")
    tracker.finish_file("file1.py", issues_found=0)
    tracker.start_file("file2.py")
    tracker.finish_file("file2.py", issues_found=0)
    
    # Check the last FILE_FINISHED event
    finished_events = [e for e in events_received if e.type == ProgressEventType.FILE_FINISHED]
    last_finished = finished_events[-1]
    
    assert abs(last_finished.percent_complete - 50.0) < 0.1, \
        f"Expected ~50%, got {last_finished.percent_complete}%"
    
    print("✅ test_progress_tracker_percentage passed!")


def test_global_tracker():
    """
    Test the global tracker functions.
    
    The global tracker allows skills to access the progress tracker
    without needing explicit references.
    """
    # Initially, no global tracker
    assert get_global_tracker() is None, "Global tracker should be None initially"
    
    # Set a tracker
    tracker = ProgressTracker(callback=None, heartbeat_interval=0)
    set_global_tracker(tracker)
    
    assert get_global_tracker() is tracker, "Global tracker should be set"
    
    # Clear the tracker
    set_global_tracker(None)
    
    assert get_global_tracker() is None, "Global tracker should be cleared"
    
    print("✅ test_global_tracker passed!")


def test_progress_event_message():
    """
    Test that events have appropriate messages.
    """
    events_received = []
    
    def callback(event: ProgressEvent):
        events_received.append(event)
    
    tracker = ProgressTracker(callback=callback, heartbeat_interval=0)
    
    tracker.start_scan("/my/project")
    tracker.set_total_files(10)
    tracker.start_file("/my/project/app.py")
    tracker.finish_file("/my/project/app.py", issues_found=5)
    tracker.finish_scan()
    
    # Check messages
    start_event = [e for e in events_received if e.type == ProgressEventType.SCAN_STARTED][0]
    assert "/my/project" in start_event.message, "Start message should include folder path"
    
    discover_event = [e for e in events_received if e.type == ProgressEventType.FILES_DISCOVERED][0]
    assert "10" in discover_event.message, "Discover message should include file count"
    
    file_start = [e for e in events_received if e.type == ProgressEventType.FILE_STARTED][0]
    assert "app.py" in file_start.message, "File start message should include filename"
    
    file_finish = [e for e in events_received if e.type == ProgressEventType.FILE_FINISHED][0]
    assert "5" in file_finish.message, "File finish message should include issue count"
    
    print("✅ test_progress_event_message passed!")


if __name__ == "__main__":
    print("\n🧪 Running progress tracking tests...\n")
    
    test_progress_tracker_basic()
    test_progress_tracker_percentage()
    test_global_tracker()
    test_progress_event_message()
    
    print("\n✅ All progress tracking tests passed!\n")
