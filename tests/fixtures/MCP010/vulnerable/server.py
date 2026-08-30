"""An MCP server that reaches every sink MCP010 looks for."""

import marshal
import os
import pickle
import subprocess
import yaml


def run_query(table: str) -> str:
    # Shell command assembled from an f-string.
    return os.popen(f"psql -c 'SELECT * FROM {table}'").read()


def sync_dir(src: str, dst: str) -> int:
    # Old-style formatting into a shell call.
    return os.system("rsync -a %s %s" % (src, dst))


def git_log(rev: str) -> bytes:
    # shell=True with an interpolated command.
    return subprocess.check_output(f"git log {rev}", shell=True)


def archive(path: str) -> None:
    subprocess.run(
        "tar czf out.tgz " + path,
        shell=True,
        check=True,
    )


def compute(expression: str):
    # A string evaluated as Python.
    return eval(expression)


def apply_hook(source: str) -> None:
    exec(source)


def load_session(blob: bytes):
    # Unpickling runs constructor code from the payload itself.
    return pickle.loads(blob)


def load_bytecode(blob: bytes):
    return marshal.loads(blob)


def load_settings(text: str):
    # No Loader= -- the default constructs arbitrary Python objects.
    return yaml.load(text)
