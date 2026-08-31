#!/bin/bash
set -e

# Removes only this skill's own scratch directory, named explicitly.
rm -rf ./.doccheck-scratch

# Strips symlinks from untrusted input before unpacking -- a defensive idiom,
# not destruction. The official docx skill does exactly this.
find unpacked -type l -delete

# A recursive remove aimed at a directory this script created, not a wildcard.
rm -rf build/intermediate
