from libdebug import debugger
import sys
import traceback
import time
import matplotlib.pyplot as plt
import numpy as np
import os

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

     #To start the debugger
    def start(self):
        try:
            self.dbg.run()
            print("Debugger started.")
        except Exception as e:
            print(f"Error starting debugger: {e}")
            traceback.print_exc()
            sys.exit(1)

       #Setting the breakpoint
    def set_breakpoint(self, func_name):
        try:
            self.bp = self.dbg.breakpoint(func_name)
            self.bp_address = self.bp.address
            print(f"Breakpoint set at function {func_name} at address {hex(self.bp_address)}")
        except Exception as e:
            print(f"Error setting breakpoint: {e}")
            traceback.print_exc()
            sys.exit(1)

      #Execution continues till result/error is found
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

      #debugger kill
    def kill(self):
        try:
            self.dbg.kill()
        except Exception as e:
            print(f"Error killing debugger: {e}")
            traceback.print_exc()
            sys.exit(1)

    def get_instruction_count(self):
        return self.instruction_count

if __name__ == "__main__":
    binary_path = "/home/mohibriyaz/Downloads/libdebug-main/examples/breakpoint/test" #path of the binary file
    debugger_instance = BreakPointDebugger(binary_path)

    try:
        # Start the debugger
        debugger_instance.start()

        # Set a breakpoint at the function 
        debugger_instance.set_breakpoint("print_message")

        execution_counts = []
        timestamps = []
        start_time = time.time()

        # Continue execution until the breakpoint is hit
        while True:
            debugger_instance.step()
            execution_counts.append(debugger_instance.get_instruction_count())
            timestamps.append(time.time() - start_time)

            if debugger_instance.get_instruction_pointer() == debugger_instance.bp_address:
                break

        # Print the number of instructions executed until the breakpoint
        print(f"Number of instructions executed until breakpoint: {debugger_instance.get_instruction_count()}")

        # Print the instruction pointer at the breakpoint
        print(f"Instruction pointer (RIP) at breakpoint: {hex(debugger_instance.get_instruction_pointer())}")

        # Calculate total execution time
        total_time = time.time() - start_time
        print(f"Total execution time: {total_time:.2f} seconds")

    except Exception as e:
        print(f"An error occurred: {e}")
        traceback.print_exc()
        debugger_instance.kill()
        sys.exit(1)
    finally:
        if 'debugger_instance' in locals():
            debugger_instance.kill()

    # Line graph plotting
    plt.figure(figsize=(14, 7))
    plt.plot(timestamps, execution_counts, label='Total Instructions Executed', color='green', marker='o', linestyle='-')

    plt.xlabel('Time in (seconds)', fontsize=14)
    plt.ylabel('Number of Instructions Executed', fontsize=14)
    plt.title('Number of Instructions Executed on Binary Over Time', fontsize=16)
    plt.grid(True, linestyle='-', alpha=0.7)

    # Highlighting key points
    max_instructions = max(execution_counts)
    max_time = timestamps[execution_counts.index(max_instructions)]
    plt.annotate(f'Max: {max_instructions} instructions', 
                 xy=(max_time, max_instructions), 
                 xytext=(max_time + (max_time * 0.1), max_instructions + (max_instructions * 0.1)), 
                 arrowprops=dict(facecolor='black', arrowstyle='->'),
                 fontsize=12, color='red')

    
    plt.legend(fontsize=12)
    plt.gca().set_facecolor('#f7f7f7')
    plt.tight_layout()

    # Directory to save the plot
    output_dir = '/home/mohibriyaz/Downloads/libdebug-main/examples/breakpoint'
    os.makedirs(output_dir, exist_ok=True)

    # Save the plot to the specified directory
    output_path = os.path.join(output_dir, 'line graph.png')
    plt.savefig(output_path)

    # histogram plotting
    plt.figure(figsize=(10, 6))
    plt.hist(execution_counts, bins=20, edgecolor='black', color='skyblue')

    plt.xlabel('Number of Instructions Executed', fontsize=14)
    plt.ylabel('Frequency', fontsize=14)
    plt.title('Histogram of Instructions Executed', fontsize=16)

    plt.grid(True, linestyle='-', alpha=0.5)
    plt.tight_layout()

    # Save the histogram 
    histogram_output_path = os.path.join(output_dir, 'histogram.png')
    plt.savefig(histogram_output_path)
    plt.show()
