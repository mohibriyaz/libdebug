import sys
import os
import time
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from libdebug import debugger

# Class to count the number of Python instructions executed
class InstructionCounter:
    def __init__(self):
        self.count = 0

    # Trace function to count each line executed
    def trace(self, frame, event, arg):
        if event == 'line':
            self.count += 1
        return self.trace

    # Start tracing Python instructions
    def start(self):
        sys.settrace(self.trace)

    # Stop tracing Python instructions
    def stop(self):
        sys.settrace(None)

    # Get the total count of instructions executed
    def get_count(self):
        return self.count

# Class to manage debugging of a binary file using libdebug
class BreakPointDebugger:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.dbg = debugger(self.binary_path)

    # Start the debugger
    def start(self):
        self.dbg.run()

    # Set a breakpoint at a specified function
    def set_breakpoint(self, func_name):
        self.bp = self.dbg.breakpoint(func_name)

    # Continue execution after hitting a breakpoint
    def continue_execution(self):
        self.dbg.cont()

    # Get the current instruction pointer
    def get_instruction_pointer(self):
        return self.dbg.rip

    # Kill the debugger process
    def kill(self):
        self.dbg.kill()

if __name__ == "__main__":
    # Record the script start time
    script_start_time = datetime.now()

    binary_path = "/home/mohibriyaz/Downloads/libdebug-main/examples/breakpoint/backtrace_test"

    # Initialize the instruction counter
    counter = InstructionCounter()
    counter.start()  # Start counting instructions

    # Initialize the breakpoint debugger with the binary path
    debugger_instance = BreakPointDebugger(binary_path)
    
    # Lists to store execution counts and timestamps
    execution_counts = []
    timestamps = []

    try:
        # Start the debugger
        debugger_instance.start()

        # Set a breakpoint at the 'print' function
        debugger_instance.set_breakpoint("print")  # Change this to the desired function name

        start_time = time.time()
        while True:
            # Continue execution until hitting the breakpoint
            debugger_instance.continue_execution()
            
            current_time = time.time()
            # Append the current count of instructions executed and the elapsed time
            execution_counts.append(counter.get_count())
            timestamps.append(current_time - start_time)

            # Break the loop after running for 60 seconds
            if current_time - start_time > 60:
                break

        # Print the current instruction pointer address
        print(f"Instruction pointer at breakpoint: {hex(debugger_instance.get_instruction_pointer())}")

    except Exception as e:
        # Print any error that occurs and stop the debugger
        print(f"An error occurred: {e}")
    finally:
        if 'debugger_instance' in locals():
            # Ensure the debugger is killed even if an error occurs
            debugger_instance.kill()

    # Stop counting instructions
    counter.stop()
    # Print the total number of instructions executed
    print(f"Number of instructions executed: {counter.get_count()}")

    # Directory to save the plot
    output_dir = '/home/mohibriyaz/Downloads/libdebug-main/examples/breakpoint'
    os.makedirs(output_dir, exist_ok=True)

    # Plot the number of instructions executed over time
    # Plot the number of instructions executed over time
plt.figure(figsize=(18, 8))
plt.plot(timestamps, execution_counts, label='Instructions Executed', color='r', marker='o')

# Label the x and y axes
plt.xlabel('Time (seconds)')
plt.ylabel('Number of Instructions Executed')

# Title for the plot
plt.title('Number of Instructions Executed Over Time During Binary Execution')

# Adding a grid for better readability
plt.grid(True)

# Format x-axis to show seconds clearly
plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%S'))

# Highlighting key points
max_instructions = max(execution_counts)
max_time = timestamps[execution_counts.index(max_instructions)]
plt.annotate(f'Max: {max_instructions} instructions', xy=(max_time, max_instructions), 
             xytext=(max_time + 5, max_instructions + 5), 
             arrowprops=dict(facecolor='black', arrowstyle='->'),
             fontsize=10, color='red')

# Add legend to the plot
plt.legend()

# Save the plot to the specified directory
output_path = os.path.join(output_dir, 'instructions_executed_over_time.png')
plt.savefig(output_path)
plt.show()  # Display the plot

  
# Print the total script duration
script_end_time = datetime.now()
print("Script duration:", script_end_time - script_start_time)
