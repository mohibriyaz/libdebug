from libdebug import debugger
import time
from datetime import datetime
import sys
import os
import matplotlib.pyplot as plt

script_start_time = datetime.now()

class InstructionCounter:
    def __init__(self):
        self.count = 0

    def trace(self, frame, event, arg):
        if event == 'line':
            self.count += 1
        return self.trace

    def start(self):
        sys.settrace(self.trace)

    def stop(self):
        sys.settrace(None)

    def get_count(self):
        return self.count

counter = InstructionCounter()
counter.start()

class BreakPointDebugger:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.dbg = debugger(self.binary_path)

    def start(self):
        self.dbg.run()

    def set_breakpoint(self, func_name):
        self.bp = self.dbg.breakpoint(func_name)

    def continue_execution(self):
        self.dbg.cont()

    def get_instruction_pointer(self):
        return self.dbg.rip

    def kill(self):
        self.dbg.kill()

if __name__ == "__main__":
    binary_path = "/home/mohibriyaz/Downloads/libdebug-main/examples/breakpoint/test"
    debugger_instance = BreakPointDebugger(binary_path)

    execution_counts = []
    timestamps = []

    try:
        debugger_instance.start()
        debugger_instance.set_breakpoint("print")

        start_time = time.time()
        while True:
            debugger_instance.continue_execution()
            current_time = time.time()
            execution_counts.append(counter.get_count())
            timestamps.append(current_time - start_time)
            
            if current_time - start_time > 60: 
                break

        print(f"Instruction pointer (RIP) at breakpoint: {hex(debugger_instance.get_instruction_pointer())}")
    except Exception as e:
        print(f"An error occurred: {e}")
        debugger_instance.kill()
        counter.stop()
        sys.exit(1)
    finally:
        if 'debugger_instance' in locals():
            debugger_instance.kill()

    counter.stop()
    print(f"Number of instructions executed: {counter.get_count()}")

    output_dir = '/home/mohibriyaz/Downloads/libdebug-main/examples/breakpoint'
    os.makedirs(output_dir, exist_ok=True)
    
    plt.plot(timestamps, execution_counts)
    plt.xlabel('Time in seconds')
    plt.ylabel('Instructions Executed')
    plt.title('Instructions Executed Over Time')
    
    output_path = os.path.join('/home/mohibriyaz/Downloads/libdebug-main/examples/breakpoint', 'instructions_executed_over_time.png')
    plt.savefig(output_path)

    script_end_time = datetime.now()
    print(script_end_time - script_start_time)
