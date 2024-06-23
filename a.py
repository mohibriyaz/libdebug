import libdebug


binary_path = "./testa"


dbg = libdebug.debugger()


pid = dbg.exec(binary_path)


dbg.wait_break()


dbg.set_breakpoint(0x1149)


dbg.cont()


dbg.wait_break()


print(dbg.get_registers())


dbg.detach()
