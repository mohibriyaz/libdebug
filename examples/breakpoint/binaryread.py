import capstone
import matplotlib.pyplot as plt
import numpy as np

def read_binary_file(file_path):
    try:
        with open(file_path, 'rb') as binary_file:
            binary_data = binary_file.read()
            return binary_data
    except Exception as e:
        print(f"Error reading: {e}")
        return None

def print_binary_data_as_hex(binary_data, bytes_per_line=16):
    for i in range(0, len(binary_data), bytes_per_line):
        line = binary_data[i:i+bytes_per_line]
        hex_values = ' '.join(f'{b:02x}' for b in line)
        print(f'{i:08x}  {hex_values}')

def disassemble_binary(binary_data, start_address=0x100000):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    instructions = md.disasm(binary_data, start_address)
    return list(instructions)  

def simulate_execution(instructions):
    instruction_count = 0
    instruction_types = {}

    for i in instructions:
        mnemonic = i.mnemonic
        instruction_count += 1

        if mnemonic not in instruction_types:
            instruction_types[mnemonic] = 0
        instruction_types[mnemonic] += 1
        
        print(f"Executing 0x{i.address:x}: {mnemonic} {i.op_str}")

    return instruction_count, instruction_types

def plot_instruction_types(instruction_types):
    categories = list(instruction_types.keys())
    counts = list(instruction_types.values())

    plt.figure(figsize=(12, 8))
    plt.bar(categories, counts, color='blue')
    plt.xlabel('Instruction Type')
    plt.ylabel('Frequency')
    plt.title('Frequency of Executed Instruction Types')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    file_path = '/home/mohibriyaz/Documents/libdebug/examples/breakpoint/backtrace_test.py'
    binary_data = read_binary_file(file_path)
    
    if binary_data is not None:
        print("Hex Dump of Binary Data:")
        print_binary_data_as_hex(binary_data)
        
        instructions = disassemble_binary(binary_data)
        print("\nSimulated Execution of Instructions:")
        instruction_count, instruction_types = simulate_execution(instructions)
        
        print(f"\nTotal Number of Instructions Executed: {instruction_count}")
        plot_instruction_types(instruction_types)
