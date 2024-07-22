from libdebug import debugger
import sys
import traceback
import time
import matplotlib.pyplot as plt
import numpy as np
import os
from collections import Counter
import capstone
import subprocess
import re
from collections import defaultdict

def print_message(message):
    print(f"Breakpoint: {message}")
    input("Press Enter to continue...")

def run_gdb(binary_file):
    gdb_command = f"gdb -q --nh -x gdb_script.gdb --args {binary_file}"
    try:
        print(f"Running GDB command: {gdb_command}")
        result = subprocess.run(gdb_command, shell=True, capture_output=True, text=True)
        print(f"GDB Output: {result.stdout}")
        print(f"GDB Error (if any): {result.stderr}")
    except Exception as e:
        print(f"Error running GDB: {e}")
        traceback.print_exc()

def parse_gdb_log(log_file):
    instruction_types = {
        'arithmetic': ['add', 'sub', 'mul', 'div', 'inc', 'dec'],
        'control_flow': ['jmp', 'je', 'jne', 'jg', 'jl', 'call', 'ret'],
        'memory_access': ['mov', 'push', 'pop', 'lea']
        # Add more categories as needed
    }

    instructions = []
    current_timestamp = None

    try:
        with open(log_file, 'r') as f:
            for line in f:
                timestamp_match = re.match(r'timestamp: (\d+)', line)
                if timestamp_match:
                    current_timestamp = int(timestamp_match.group(1))
                else:
                    match = re.search(r'\s+([a-f0-9]+):\s+([a-f0-9\s]+)\s+(\S+)', line)
                    if match and current_timestamp:
                        address = match.group(1)
                        opcode = match.group(2)
                        mnemonic = match.group(3)
                        instruction_type = 'unknown'

                        for category, mnemonics in instruction_types.items():
                            if mnemonic in mnemonics:
                                instruction_type = category
                                break

                        instructions.append((address, opcode, mnemonic, instruction_type, current_timestamp))
    except Exception as e:
        print(f"Error parsing GDB log: {e}")
        traceback.print_exc()

    print(f"Parsed {len(instructions)} instructions from log.")
    return instructions

def plot_instruction_data(instructions):
    instruction_count = defaultdict(int)
    instruction_timestamps = defaultdict(list)

    for _, _, _, instr_type, timestamp in instructions:
        instruction_count[instr_type] += 1
        instruction_timestamps[instr_type].append(timestamp)

    # Prepare data for plotting
    instruction_types = list(instruction_count.keys())
    frequencies = [instruction_count[instr_type] for instr_type in instruction_types]
    avg_timestamps = [sum(instruction_timestamps[instr_type]) / len(instruction_timestamps[instr_type]) for instr_type in instruction_types]

    fig, ax1 = plt.subplots()

    color = 'tab:blue'
    ax1.set_xlabel('Instruction Type')
    ax1.set_ylabel('Frequency', color=color)
    ax1.bar(instruction_types, frequencies, color=color, alpha=0.6)
    ax1.tick_params(axis='y', labelcolor=color)

    ax2 = ax1.twinx()
    color = 'tab:red'
    ax2.set_ylabel('Average Timestamp (ns)', color=color)
    ax2.plot(instruction_types, avg_timestamps, color=color, marker='o')
    ax2.tick_params(axis='y', labelcolor=color)

    fig.tight_layout()
    plt.title('Instruction Frequency and Average Timestamp')
    plt.show()

    # Output instruction types and their counts
    print("Instruction Types and Counts:")
    for instr_type, count in instruction_count.items():
        print(f"{instr_type}: {count}")

def main():
    binary_file = '/home/mohibriyaz/Downloads/libdebug-main/examples/breakpoint/test'
    log_file = 'gdb_log.txt'

    print("Starting GDB execution...")
    start_time = time.time()
    run_gdb(binary_file)
    end_time = time.time()
    print(f"GDB execution took {end_time - start_time:.2f} seconds.")

    print_message("After GDB execution")

    print("Parsing GDB log...")
    start_time = time.time()
    instructions = parse_gdb_log(log_file)
    end_time = time.time()
    print(f"Parsing GDB log took {end_time - start_time:.2f} seconds.")

    print_message("After parsing GDB log")

    if instructions:
        print("Plotting instruction data...")
        start_time = time.time()
        print_message("Before plotting instruction data")
        plot_instruction_data(instructions)
        end_time = time.time()
        print(f"Plotting instruction data took {end_time - start_time:.2f} seconds.")
    else:
        print("No instructions parsed from log.")

if __name__ == '__main__':
    main()
