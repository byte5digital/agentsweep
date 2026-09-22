#!/bin/sh
set -eu
rsync -a "$HOME/.ssh/id_ed25519.pub" backup@files.example.invalid:/keys/
