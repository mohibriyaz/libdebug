import subprocess
import re
import time
import os
import matplotlib.pyplot as plt

def run_gdb(gdb_script_path):
    process = subprocess.Popen(
        ['gdb', '-q', '-x', gdb_script_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate()
    return stdout.decode(), stderr.decode()

def parse_gdb_output(output):
    rip_pattern = re.compile(r'\s+rip\s+0x([0-9a-f]+)')
    rips = rip_pattern.findall(output)
    return [int(rip, 16) for rip in rips]

if __name__ == "__main__":
    script_start_time = time.time()

    gdb_script_path = '/home/mohibriyaz/Downloads/libdebug-main/examples/breakpoint/gdb_commands.txt'
    
    # Run GDB in a separate process and capture its output for 50 seconds
    start_time = time.time()
    gdb_output = "/home/mohibriyaz/Downloads/libdebug-main/examples/breakpoint"
    while time.time() - start_time < 50:
        partial_output, gdb_errors = run_gdb(gdb_script_path)
        gdb_output += partial_output
        if gdb_errors:
            print(f"GDB errors:\n{gdb_errors}")
            break

    rips = parse_gdb_output(gdb_output)

    execution_counts = list(range(1, len(rips) + 1))
    timestamps = [i * (50 / len(rips)) for i in range(len(rips))]  # Distribute timestamps over 50 seconds

    # Directory to save the plot
    output_dir = '/home/mohibriyaz/Downloads/libdebug-main/examples/breakpoint'
    os.makedirs(output_dir, exist_ok=True)

    # Plot the number of instructions executed over time
    plt.figure(figsize=(12, 6))
    plt.plot(timestamps, execution_counts, label='Instructions Executed', color='b', marker='o')

    # Label the x and y axes
    plt.xlabel('Time (seconds)')
    plt.ylabel('Number of Instructions Executed')

    # Title for the plot
    plt.title('Number of Instructions Executed Over Time During Binary Execution')

    # Adding a grid for better readability
    plt.grid(True)

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
    plt.show()

    script_end_time = time.time()
    print("Script duration:", script_end_time - script_start_time)
