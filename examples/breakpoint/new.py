import sys
import traceback
import time
import matplotlib.pyplot as plt
import numpy as np
import os
import capstone
from libdebug import debugger

class BreakPointDebugger:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        try:
            self.dbg = debugger(self.binary_path)
        except Exception as e:
            print(f"Error initializing debugger: {e}")
            traceback.print_exc()
            sys.exit(1)
        self.bp = None
        self.bp_address = None
        self.instruction_count = 0
        self.instruction_types = []
        self.disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.execution_counts = []
        self.timestamps = []
        self.instruction_times = []

    def start(self):
        try:
            self.dbg.run()
            print("Debugger started.")
        except Exception as e:
            print(f"Error starting debugger: {e}")
            traceback.print_exc()
            sys.exit(1)

    def set_breakpoint(self, func_name):
        try:
            self.bp = self.dbg.breakpoint(func_name)
            self.bp_address = self.bp.address
            print(f"Breakpoint set at function {func_name} at address {hex(self.bp_address)}")
        except Exception as e:
            print(f"Error setting breakpoint: {e}")
            traceback.print_exc()
            sys.exit(1)

    def continue_execution(self):
        try:
            self.dbg.cont()
        except Exception as e:
            print(f"Error continuing execution: {e}")
            traceback.print_exc()
            sys.exit(1)

    def step(self):
        try:
            self.dbg.step()
            rip = self.get_instruction_pointer()
            disassembled = self.read_memory(rip)
            for insn in disassembled:
                instruction_type = insn.mnemonic
                self.instruction_types.append(instruction_type)
                self.categorize_instruction(instruction_type)
                self.execution_counts.append(self.instruction_count)
                self.timestamps.append(time.time() - self.start_time)
                self.instruction_times.append(time.time() - self.last_step_time)
                self.last_step_time = time.time()
                self.instruction_count += 1
        except Exception as e:
            print(f"Error stepping: {e}")
            traceback.print_exc()
            sys.exit(1)

    def get_instruction_pointer(self):
        try:
            return self.dbg.rip
        except Exception as e:
            print(f"Error getting instruction pointer: {e}")
            traceback.print_exc()
            sys.exit(1)

    def read_memory(self, rip, block_size=16):
        try:
            memory = self.dbg.read_memory(rip, block_size)
            return self.disassembler.disasm(memory, rip)
        except Exception as e:
            print(f"Error reading memory: {e}")
            traceback.print_exc()
            return []

    def categorize_instruction(self, instruction_type):
        # Prints categories, same logic as before
        # Add more categories if needed
        pass

    def kill(self):
        try:
            self.dbg.kill()
        except Exception as e:
            print(f"Error killing debugger: {e}")
            traceback.print_exc()
            sys.exit(1)

    def get_instruction_count(self):
        return self.instruction_count

    def get_instruction_types(self):
        return self.instruction_types
        
    def plot_results(self):
        plt.figure(figsize=(14, 7))
        plt.plot(self.timestamps, self.execution_counts, label='Total Instructions Executed', color='green', marker='o', linestyle='-')
        plt.xlabel('Time in (seconds)')
        plt.ylabel('Number of Instructions Executed')
        plt.title('Number of Instructions Executed Over Time')
        plt.grid(True, linestyle='--', alpha=0.2)
        plt.legend()
        plt.show()

if __name__ == "__main__":
    binary_path = "/home/mohibriyaz/Documents/libdebug/examples/breakpoint/memory_test"
    debugger_instance = BreakPointDebugger(binary_path)

    try:
        debugger_instance.start()
        debugger_instance.set_breakpoint("main")  # Example: main function
        debugger_instance.start_time = time.time()
        debugger_instance.last_step_time = debugger_instance.start_time

        while debugger_instance.get_instruction_count() < 100:  # Limit for demonstration
            debugger_instance.step()
            if debugger_instance.get_instruction_pointer() == debugger_instance.bp_address:
                print("Reached breakpoint. Exiting.")
                break

    except Exception as e:
        print(f"An error occurred during debugging: {e}")
        traceback.print_exc()
    finally:
        debugger_instance.kill()
        debugger_instance.plot_results()
