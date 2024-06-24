#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger


class SignalMultithreadTest(unittest.TestCase):
    def test_signal_multithread_undet_hook_block(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        def hook_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def hook_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def hook_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            SIGINT_count += 1

        def hook_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count

            SIGQUIT_count += 1

        def hook_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger("binaries/signals_multithread_undet_test")

        r = d.run()

        hook1 = d.hook_signal(10, callback=hook_SIGUSR1)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)
        hook3 = d.hook_signal(2, callback=hook_SIGINT)
        hook4 = d.hook_signal("SIGQUIT", callback=hook_SIGQUIT)
        hook5 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE)

        d.signals_to_block = ["SIGUSR1", 15, "SIGINT", 3, 13]

        d.cont()

        r.sendline(b"sync")
        r.sendline(b"sync")

        # Receive the exit message
        r.recvline(2)

        d.kill()

        self.assertEqual(SIGUSR1_count, 4)
        self.assertEqual(SIGTERM_count, 4)
        self.assertEqual(SIGINT_count, 4)
        self.assertEqual(SIGQUIT_count, 6)
        self.assertEqual(SIGPIPE_count, 6)

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)
        self.assertEqual(SIGINT_count, hook3.hit_count)
        self.assertEqual(SIGQUIT_count, hook4.hit_count)
        self.assertEqual(SIGPIPE_count, hook5.hit_count)

    def test_signal_multithread_undet_pass(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        def hook_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def hook_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def hook_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            SIGINT_count += 1

        def hook_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count

            SIGQUIT_count += 1

        def hook_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger("binaries/signals_multithread_undet_test")

        r = d.run()

        hook1 = d.hook_signal("SIGUSR1", callback=hook_SIGUSR1)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)
        hook3 = d.hook_signal("SIGINT", callback=hook_SIGINT)
        hook4 = d.hook_signal("SIGQUIT", callback=hook_SIGQUIT)
        hook5 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE)

        d.cont()

        received = []
        for _ in range(24):
            received.append(r.recvline())

        r.sendline(b"sync")
        r.sendline(b"sync")

        received.append(r.recvline())
        received.append(r.recvline())

        d.kill()

        self.assertEqual(SIGUSR1_count, 4)
        self.assertEqual(SIGTERM_count, 4)
        self.assertEqual(SIGINT_count, 4)
        self.assertEqual(SIGQUIT_count, 6)
        self.assertEqual(SIGPIPE_count, 6)

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)
        self.assertEqual(SIGINT_count, hook3.hit_count)
        self.assertEqual(SIGQUIT_count, hook4.hit_count)
        self.assertEqual(SIGPIPE_count, hook5.hit_count)

        # Count the number of times each signal was received
        self.assertEqual(received.count(b"Received signal 10"), 4)
        self.assertEqual(received.count(b"Received signal 15"), 4)
        self.assertEqual(received.count(b"Received signal 2"), 4)
        self.assertEqual(received.count(b"Received signal 3"), 6)
        self.assertEqual(received.count(b"Received signal 13"), 6)
        # Note: sometimes the signals are passed to ptrace once and received twice
        # Maybe another ptrace/kernel/whatever problem in multithreaded programs (?)
        # Using raise(sig) instead of kill(pid, sig) to send signals in the original
        # program seems to mitigate the problem for whatever reason
        # I will investigate this further in the future, but for now this is fine

    def test_signal_multithread_det_hook_block(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0
        tids = []

        def hook_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count
            nonlocal tids

            SIGUSR1_count += 1
            tids.append(t.thread_id)

        def hook_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count
            nonlocal tids

            SIGTERM_count += 1
            tids.append(t.thread_id)

        def hook_SIGINT(t, signal_number):
            nonlocal SIGINT_count
            nonlocal tids

            SIGINT_count += 1
            tids.append(t.thread_id)

        def hook_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count
            nonlocal tids

            SIGQUIT_count += 1
            tids.append(t.thread_id)

        def hook_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count
            nonlocal tids

            SIGPIPE_count += 1
            tids.append(t.thread_id)

        d = debugger("binaries/signals_multithread_det_test")

        r = d.run()

        hook1 = d.hook_signal(10, callback=hook_SIGUSR1)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)
        hook3 = d.hook_signal(2, callback=hook_SIGINT)
        hook4 = d.hook_signal("SIGQUIT", callback=hook_SIGQUIT)
        hook5 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE)

        d.signals_to_block = ["SIGUSR1", 15, "SIGINT", 3, 13]

        d.cont()

        # Receive the exit message
        r.recvline(timeout=15)
        r.sendline(b"sync")
        r.recvline()

        receiver = d.threads[1].thread_id
        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2)
        self.assertEqual(SIGINT_count, 2)
        self.assertEqual(SIGQUIT_count, 3)
        self.assertEqual(SIGPIPE_count, 3)

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)
        self.assertEqual(SIGINT_count, hook3.hit_count)
        self.assertEqual(SIGQUIT_count, hook4.hit_count)
        self.assertEqual(SIGPIPE_count, hook5.hit_count)

        set_tids = set(tids)
        self.assertEqual(len(set_tids), 1)
        self.assertEqual(set_tids.pop(), receiver)

    def test_signal_multithread_det_pass(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0
        tids = []

        def hook_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count
            nonlocal tids

            SIGUSR1_count += 1
            tids.append(t.thread_id)

        def hook_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count
            nonlocal tids

            SIGTERM_count += 1
            tids.append(t.thread_id)

        def hook_SIGINT(t, signal_number):
            nonlocal SIGINT_count
            nonlocal tids

            SIGINT_count += 1
            tids.append(t.thread_id)

        def hook_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count
            nonlocal tids

            SIGQUIT_count += 1
            tids.append(t.thread_id)

        def hook_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count
            nonlocal tids

            SIGPIPE_count += 1
            tids.append(t.thread_id)

        d = debugger("binaries/signals_multithread_det_test")

        r = d.run()

        hook1 = d.hook_signal("SIGUSR1", callback=hook_SIGUSR1)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)
        hook3 = d.hook_signal("SIGINT", callback=hook_SIGINT)
        hook4 = d.hook_signal("SIGQUIT", callback=hook_SIGQUIT)
        hook5 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE)

        d.cont()

        received = []
        for _ in range(13):
            received.append(r.recvline(timeout=5))

        r.sendline(b"sync")
        received.append(r.recvline(timeout=5))

        receiver = d.threads[1].thread_id
        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2)
        self.assertEqual(SIGINT_count, 2)
        self.assertEqual(SIGQUIT_count, 3)
        self.assertEqual(SIGPIPE_count, 3)

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)
        self.assertEqual(SIGINT_count, hook3.hit_count)
        self.assertEqual(SIGQUIT_count, hook4.hit_count)
        self.assertEqual(SIGPIPE_count, hook5.hit_count)

        # Count the number of times each signal was received
        self.assertEqual(received.count(b"Received signal on receiver 10"), 2)
        self.assertEqual(received.count(b"Received signal on receiver 15"), 2)
        self.assertEqual(received.count(b"Received signal on receiver 2"), 2)
        self.assertEqual(received.count(b"Received signal on receiver 3"), 3)
        self.assertEqual(received.count(b"Received signal on receiver 13"), 3)

        set_tids = set(tids)
        self.assertEqual(len(set_tids), 1)
        self.assertEqual(set_tids.pop(), receiver)

    def test_signal_multithread_send_signal(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0
        tids = []

        def hook_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count
            nonlocal tids

            SIGUSR1_count += 1
            tids.append(t.thread_id)

        def hook_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count
            nonlocal tids

            SIGTERM_count += 1
            tids.append(t.thread_id)

        def hook_SIGINT(t, signal_number):
            nonlocal SIGINT_count
            nonlocal tids

            SIGINT_count += 1
            tids.append(t.thread_id)

        def hook_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count
            nonlocal tids

            SIGQUIT_count += 1
            tids.append(t.thread_id)

        def hook_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count
            nonlocal tids

            SIGPIPE_count += 1
            tids.append(t.thread_id)

        d = debugger("binaries/signals_multithread_det_test")

        # Set a breakpoint to stop the program before the end of the receiver thread
        r = d.run()

        bp = d.breakpoint(0x15A8, hardware=True)

        hook1 = d.hook_signal("SIGUSR1", callback=hook_SIGUSR1)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)
        hook3 = d.hook_signal("SIGINT", callback=hook_SIGINT)
        hook4 = d.hook_signal("SIGQUIT", callback=hook_SIGQUIT)
        hook5 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE)

        d.cont()

        received = []
        for _ in range(13):
            received.append(r.recvline(timeout=5))

        r.sendline(b"sync")

        d.wait()
        if bp.hit_on(d.threads[1]):
            d.threads[1].signal = "SIGUSR1"
            d.cont()
        received.append(r.recvline(timeout=5))
        received.append(r.recvline(timeout=5))

        receiver = d.threads[1].thread_id
        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2)
        self.assertEqual(SIGINT_count, 2)
        self.assertEqual(SIGQUIT_count, 3)
        self.assertEqual(SIGPIPE_count, 3)

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)
        self.assertEqual(SIGINT_count, hook3.hit_count)
        self.assertEqual(SIGQUIT_count, hook4.hit_count)
        self.assertEqual(SIGPIPE_count, hook5.hit_count)

        # Count the number of times each signal was received
        self.assertEqual(received.count(b"Received signal on receiver 10"), 3)
        self.assertEqual(received.count(b"Received signal on receiver 15"), 2)
        self.assertEqual(received.count(b"Received signal on receiver 2"), 2)
        self.assertEqual(received.count(b"Received signal on receiver 3"), 3)
        self.assertEqual(received.count(b"Received signal on receiver 13"), 3)

        set_tids = set(tids)
        self.assertEqual(len(set_tids), 1)
        self.assertEqual(set_tids.pop(), receiver)
