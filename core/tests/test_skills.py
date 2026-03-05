"""
Unit tests for AgentSec skills.

These tests verify that each skill function works correctly
without needing a connection to Copilot.
"""

import asyncio
import os
import tempfile
import pytest

from agentsec.skills import list_files, analyze_file, generate_report


@pytest.mark.asyncio
async def test_list_files_returns_files():
    """list_files should return files in a directory."""
    # Create a temporary directory with some files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test files
        for name in ["file1.py", "file2.txt", "file3.js"]:
            file_path = os.path.join(temp_dir, name)
            with open(file_path, "w") as f:
                f.write("# test content")

        result = await list_files(temp_dir)

        assert result["total"] == 3
        assert len(result["files"]) == 3
        assert result["folder"] == temp_dir


@pytest.mark.asyncio
async def test_list_files_nonexistent_folder():
    """list_files should handle missing folders gracefully."""
    result = await list_files("/nonexistent/folder/path")
    assert result["total"] == 0
    assert "error" in result


@pytest.mark.asyncio
async def test_analyze_file_finds_eval():
    """analyze_file should detect eval() calls."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("result = eval(user_input)\n")
        temp_path = f.name

    try:
        result = await analyze_file(temp_path)
        assert result["severity"] == "error"
        assert any(i["type"] == "unsafe-eval" for i in result["issues"])
    finally:
        os.unlink(temp_path)


@pytest.mark.asyncio
async def test_analyze_file_finds_hardcoded_secret():
    """analyze_file should detect hardcoded passwords."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write('db_password="hunter2"\n')
        temp_path = f.name

    try:
        result = await analyze_file(temp_path)
        assert any(i["type"] == "hardcoded-secret" for i in result["issues"])
    finally:
        os.unlink(temp_path)


@pytest.mark.asyncio
async def test_analyze_file_clean_file():
    """analyze_file should return no issues for clean code."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("def hello():\n    print('Hello World')\n")
        temp_path = f.name

    try:
        result = await analyze_file(temp_path)
        assert result["severity"] == "info"
        assert len(result["issues"]) == 0
    finally:
        os.unlink(temp_path)


@pytest.mark.asyncio
async def test_generate_report_with_issues():
    """generate_report should produce correct summary statistics."""
    mock_findings = [
        {
            "file": "app.py",
            "issues": [
                {"type": "unsafe-eval", "message": "eval found", "severity": "HIGH", "line": 5},
                {"type": "hardcoded-secret", "message": "password found", "severity": "MEDIUM", "line": 10},
            ],
            "severity": "error",
        },
        {
            "file": "utils.py",
            "issues": [],
            "severity": "info",
        },
    ]

    report = await generate_report(mock_findings)

    assert report["total_files"] == 2
    assert report["total_issues"] == 2
    assert report["high_count"] == 1
    assert report["medium_count"] == 1
    assert report["low_count"] == 0
    assert "app.py" in report["files_with_issues"]


@pytest.mark.asyncio
async def test_generate_report_no_issues():
    """generate_report should handle clean codebases."""
    mock_findings = [
        {"file": "clean.py", "issues": [], "severity": "info"},
    ]

    report = await generate_report(mock_findings)

    assert report["total_issues"] == 0
    assert "No security issues found" in report["summary"]
