"""The same server, written so none of MCP010's conditions hold."""

import json
import os
import subprocess
import yaml


def run_query(table: str) -> bytes:
    # Arguments as a list, no shell: nothing parses metacharacters.
    return subprocess.check_output(["psql", "-c", f"SELECT * FROM {table}"])


def sync_dir(src: str, dst: str) -> None:
    # shell=False (the default), so the f-string is not a shell command.
    subprocess.run(["rsync", "-a", src, dst], check=True)


def fixed_shell_command() -> int:
    # A shell call, but with nothing interpolated into it.
    return os.system("rsync --version")


def literal_shell_pipeline() -> int:
    return subprocess.call("ls -la | wc -l", shell=True)


def evaluate_expression(name: str):
    # A lookup table of known-safe callables, not a dynamic evaluator.
    handlers = {"sum": sum, "min": min, "max": max}
    return handlers[name]


def run_sql(cursor, table: str):
    # cursor.execute() is SQL, not process execution -- a different rule's
    # concern, and explicitly not this one's.
    cursor.execute(f"SELECT * FROM {table}")


def load_session(blob: str):
    return json.loads(blob)


def load_settings(text: str):
    return yaml.safe_load(text)


def load_settings_explicit(text: str):
    return yaml.load(text, Loader=yaml.SafeLoader)


def describe() -> str:
    # Deliberately worded without the trigger substrings: this rule matches raw
    # text, so prose that spells a sink out verbatim would match it. Same
    # accepted limitation MCP008 documents for TypeScript.
    return "This server runs no evaluator and spawns no shell; it uses argument lists."
