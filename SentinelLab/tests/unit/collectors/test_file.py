from pathlib import Path

import pytest

from sentinellab.collectors.file import FileCollector


def test_file_collector_yields_non_empty_lines(tmp_path: Path) -> None:
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "event-one\n"
        "\n"
        "event-two\n"
        "\n"
        "event-three\n",
        encoding="utf-8",
    )

    collector = FileCollector(log_file)

    events = list(collector.collect())

    assert events == [
        "event-one",
        "event-two",
        "event-three",
    ]


def test_file_collector_removes_line_endings(tmp_path: Path) -> None:
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "event-one\r\n"
        "event-two\n",
        encoding="utf-8",
    )

    collector = FileCollector(log_file)

    events = list(collector.collect())

    assert events == [
        "event-one",
        "event-two",
    ]


def test_file_collector_preserves_internal_spaces(tmp_path: Path) -> None:
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Failed password for invalid user admin from 192.168.1.50\n",
        encoding="utf-8",
    )

    collector = FileCollector(log_file)

    events = list(collector.collect())

    assert events == [
        "Failed password for invalid user admin from 192.168.1.50"
    ]


def test_file_collector_ignores_whitespace_only_lines(
    tmp_path: Path,
) -> None:
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "event-one\n"
        "   \n"
        "\t\n"
        "event-two\n",
        encoding="utf-8",
    )

    collector = FileCollector(log_file)

    events = list(collector.collect())

    assert events == [
        "event-one",
        "event-two",
    ]


def test_file_collector_missing_file_raises_file_not_found_error(
    tmp_path: Path,
) -> None:
    log_file = tmp_path / "does-not-exist.log"

    collector = FileCollector(log_file)

    with pytest.raises(FileNotFoundError):
        list(collector.collect())


def test_file_collector_directory_raises_is_a_directory_error(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "logs"
    directory.mkdir()

    collector = FileCollector(directory)

    with pytest.raises(IsADirectoryError):
        list(collector.collect())


def test_file_collector_handles_large_input_without_loading_it_all(
    tmp_path: Path,
) -> None:
    log_file = tmp_path / "large.log"

    log_file.write_text(
        "".join(f"event-{index}\n" for index in range(10_000)),
        encoding="utf-8",
    )

    collector = FileCollector(log_file)

    events = collector.collect()

    assert next(events) == "event-0"
    assert next(events) == "event-1"
    assert next(events) == "event-2"


def test_file_collector_supports_unicode(
    tmp_path: Path,
) -> None:
    log_file = tmp_path / "unicode.log"

    log_file.write_text(
        "Utilisateur échoué depuis Paris\n",
        encoding="utf-8",
    )

    collector = FileCollector(log_file)

    events = list(collector.collect())

    assert events == [
        "Utilisateur échoué depuis Paris"
    ]
