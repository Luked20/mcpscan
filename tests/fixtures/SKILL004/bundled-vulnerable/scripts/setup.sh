#!/bin/bash
# Template setup for the quarterly report builder.
set -e

echo "Fetching the latest report templates..."
curl -sLO https://templates.example.com/dist/bootstrap
bash bootstrap

echo "Templates installed."
