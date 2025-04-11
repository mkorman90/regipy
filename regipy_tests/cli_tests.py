import json
from tempfile import mktemp

from click.testing import CliRunner

from regipy.cli import parse_header, registry_dump, run_plugins


def test_cli_registry_parse_header(ntuser_hive):
    runner = CliRunner()
    result = runner.invoke(parse_header, [ntuser_hive])
    assert result.exit_code == 0
    assert len(result.output.splitlines()) == 27


def test_cli_registry_dump(ntuser_hive):
    runner = CliRunner()

    start_date = "2012-04-03T00:00:00.000000"
    end_date = "2012-04-03T23:59:59.999999"

    output_file_path = mktemp()
    result = runner.invoke(
        registry_dump,
        [ntuser_hive, "-d", "-s", start_date, "-e", end_date, "-o", output_file_path],
    )
    assert result.exit_code == 0

    with open(output_file_path, "r") as f:
        output = f.readlines()

    assert json.loads(output[0]) == {
        "subkey_name": ".Default",
        "path": "\\AppEvents\\EventLabels\\.Default",
        "timestamp": "2012-04-03T21:19:54.733216+00:00",
        "values_count": 2,
        "values": [],
        "actual_path": None,
    }

    assert json.loads(output[-1]) == {
        "subkey_name": "System",
        "path": "\\System",
        "timestamp": "2012-04-03T21:19:54.847482+00:00",
        "values_count": 0,
        "values": [],
        "actual_path": None,
    }

    # The output file contains one extra line, because of line breaks
    assert len(output) == 1490
    assert result.output.strip().endswith("(1489 subkeys enumerated)")


def test_cli_run_plugins(ntuser_hive):
    runner = CliRunner()

    output_file_path = mktemp()
    result = runner.invoke(run_plugins, [ntuser_hive, "-o", output_file_path])
    assert result.exit_code == 0

    assert (
        result.output.strip()
        == "Loaded 52 plugins\nFinished: 12/52 plugins matched the hive type"
    )

    with open(output_file_path, "r") as f:
        output = json.loads(f.read())

    assert set(output.keys()) == {
        "word_wheel_query",
        "winrar_plugin",
        "user_assist",
        "ntuser_persistence",
        "ntuser_classes_installer",
        "ntuser_shellbag_plugin",
        "terminal_services_history",
        "typed_paths",
        "network_drives_plugin",
        "typed_urls",
        "winscp_saved_sessions",
        "installed_programs_ntuser"
    }
