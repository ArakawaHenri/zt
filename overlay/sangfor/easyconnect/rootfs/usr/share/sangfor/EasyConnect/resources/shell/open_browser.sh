#!/bin/bash
# EasyConnect hands the web resources it wants opened to this script, the
# address being its second argument. Pass it on to xdg-open, which writes it down.
exec /usr/bin/xdg-open "${2:-$1}"
