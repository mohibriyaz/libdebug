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
    
    instruction_count = 0
    instruction_types = {
        "data_movement": [],
        "arithmetic": [],
        "logical": [],
        "control_flow": [],
        "comparison": [],
        "stack": [],
        "string": [],
        "bit_manipulation": [],
        "floating_point": [],
        "system": [],
        "other": []
    }
    
    # Define the sets of mnemonics for each type of instruction
    data_movement_instructions = {"mov", "push", "pop", "lea", "movzx", "movsx", "xchg", "movs", "cmps"}
    arithmetic_instructions = {"add", "sub", "mul", "div", "inc", "dec", "neg", "adc", "sbb", "imul", "idiv"}
    logical_instructions = {"and", "or", "xor", "not", "test"}
    control_flow_instructions = {"jmp", "je", "jne", "jg", "jl", "jge", "jle", "call", "ret", "loop"}
    comparison_instructions = {"cmp", "test"}
    stack_instructions = {"push", "pop"}
    string_instructions = {"movs", "cmps", "scas"}
    bit_manipulation_instructions = {"shl", "sal", "shr", "rol", "ror"}
    floating_point_instructions = {"fadd", "fsub", "fmul", "fdiv"}
    system_instructions = {"int", "hlt"}
    
    for i in instructions:
        instruction_count += 1
        mnemonic = i.mnemonic
        
        if mnemonic in data_movement_instructions:
            instruction_types["data_movement"].append(mnemonic)
        elif mnemonic in arithmetic_instructions:
            instruction_types["arithmetic"].append(mnemonic)
        elif mnemonic in logical_instructions:
            instruction_types["logical"].append(mnemonic)
        elif mnemonic in control_flow_instructions:
            instruction_types["control_flow"].append(mnemonic)
        elif mnemonic in comparison_instructions:
            instruction_types["comparison"].append(mnemonic)
        elif mnemonic in stack_instructions:
            instruction_types["stack"].append(mnemonic)
        elif mnemonic in string_instructions:
            instruction_types["string"].append(mnemonic)
        elif mnemonic in bit_manipulation_instructions:
            instruction_types["bit_manipulation"].append(mnemonic)
        elif mnemonic in floating_point_instructions:
            instruction_types["floating_point"].append(mnemonic)
        elif mnemonic in system_instructions:
            instruction_types["system"].append(mnemonic)
        else:
            instruction_types["other"].append(mnemonic)
        
        print(f"0x{i.address:x}:\t{mnemonic}\t{i.op_str}")
    
    return instruction_count, instruction_types

def plot_combined(instruction_count, instruction_types):
    fig, axs = plt.subplots(2, 1, figsize=(12, 16))
    
    # Plot Instruction Count
    axs[0].plot(range(instruction_count), range(1, instruction_count + 1), label='Instruction Count', color='blue', marker='o', linestyle='-')
    axs[0].set_xlabel('Instruction Index')
    axs[0].set_ylabel('Number of Instructions')
    axs[0].set_title('Number of Instructions Executed')
    axs[0].legend()
    axs[0].grid(True)

    # Plot Instruction Types
    all_types = []
    all_counts = []
    for category, mnemonics in instruction_types.items():
        unique_types, counts = np.unique(mnemonics, return_counts=True)
        all_types.extend(unique_types)
        all_counts.extend(counts)
        axs[1].bar(unique_types, counts, label=category.capitalize())

    axs[1].set_xlabel('Instruction Type')
    axs[1].set_ylabel('Frequency')
    axs[1].set_title('Frequency of Instruction Types')
    axs[1].legend()
    axs[1].grid(True)
    axs[1].set_xticklabels(all_types, rotation=90)
    
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    file_path = '/home/mohibriyaz/Documents/libdebug/examples/breakpoint/test'
    binary_data = read_binary_file(file_path)
    
    if binary_data is not None:
        print("Hex Dump of Binary Data:")
        print_binary_data_as_hex(binary_data)
        print("\nDisassembled Instructions:")
        
        instruction_count, instruction_types = disassemble_binary(binary_data)
        
        print(f"\nTotal Number of Instructions: {instruction_count}")
        
        plot_combined(instruction_count, instruction_types)
