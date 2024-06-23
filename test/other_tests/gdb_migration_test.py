#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug import debugger, libcontext

d = debugger("binaries/basic_test")

libcontext.terminal = ["tmux", "splitw", "-h"]
# libcontext.terminal = ["gnome-terminal", "--tab", "--"]

d.run()

bp = d.breakpoint("register_test")

d.step()
d.step()

print(hex(d.rip))

d.migrate_to_gdb()

print(hex(d.rip))

d.cont()
d.wait()

print(hex(d.rip))

d.step()

print(hex(d.rip))

d.kill()
