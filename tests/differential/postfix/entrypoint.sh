#!/bin/sh
set -eu
postfix check
exec postfix start-fg
