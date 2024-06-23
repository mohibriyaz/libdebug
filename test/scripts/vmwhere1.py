#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

#
# vmwhere1 - challenge from UIUCTF 2023
#

import string
import unittest

from libdebug import debugger


class Vmwhere1(unittest.TestCase):
    def setUp(self):
        pass

    def test_vmwhere1(self):
        flag = b""
        counter = 3
        stop = False

        d = debugger(["CTF/vmwhere1", "CTF/vmwhere1_program"])

        while not stop:
            for el in string.printable:
                r = d.run()
                bp = d.breakpoint(0x1587, hardware=True)
                d.cont()

                r.recvline()
                r.recvuntil(b"the password:\n")

                r.sendline(flag + el.encode())


                while d.rip == bp.address:
                    d.cont()

                message = r.recvline()

                if b"Incorrect" not in message:
                    flag += el.encode()
                    stop = True
                    d.kill()
                    break
                else:
                    if bp.hit_count > counter:
                        counter = bp.hit_count
                        flag += el.encode()
                        d.kill()
                        break

                d.kill()

        self.assertEqual(
            flag, b"uiuctf{ar3_y0u_4_r3al_vm_wh3r3_(gpt_g3n3r4t3d_th1s_f14g)}"
        )

    def test_vmwhere1_callback(self):
        flag = b""
        counter = 3
        stop = False

        d = debugger(["CTF/vmwhere1", "CTF/vmwhere1_program"])

        def callback(d, bp):
            pass

        while not stop:
            for el in string.printable:
                r = d.run()
                bp = d.breakpoint(0x1587, hardware=True, callback=callback)
                d.cont()

                r.recvline()
                r.recvuntil(b"the password:\n")

                r.sendline(flag + el.encode())


                message = r.recvline()

                if b"Incorrect" not in message:
                    flag += el.encode()
                    stop = True
                    d.kill()
                    break
                else:
                    if bp.hit_count > counter:
                        counter = bp.hit_count
                        flag += el.encode()
                        d.kill()
                        break

                d.kill()

        self.assertEqual(
            flag, b"uiuctf{ar3_y0u_4_r3al_vm_wh3r3_(gpt_g3n3r4t3d_th1s_f14g)}"
        )


if __name__ == "__main__":
    unittest.main()
