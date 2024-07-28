import sys
import traceback
import time
import matplotlib.pyplot as plt
import numpy as np
import os
import capstone
from libdebug import debugger
import capstone

class BreakPointDebugger:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.binary_data = None
        self.data = []
        self.idx = 0
        self.mnemonics =[]
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

        # Categories of instructions
        self.data_movement_instructions = {"mov", "push", "pop", "lea", "movzx", "movsx", "xchg", "movs", "cmps"}
        self.arithmetic_instructions = {"add", "sub", "mul", "div", "inc", "dec", "neg", "adc", "sbb", "imul", "idiv"}
        self.logical_instructions = {"and", "or", "xor", "not", "test"}
        self.control_flow_instructions = {"jmp", "je", "jne", "jg", "jl", "jge", "jle", "call", "ret", "loop"}
        self.comparison_instructions = {"cmp", "test"}
        self.stack_instructions = {"push", "pop"}
        self.string_instructions = {"movs", "cmps", "scas"}
        self.bit_manipulation_instructions = {"shl", "sal", "shr", "rol", "ror"}
        self.floating_point_instructions = {"fadd", "fsub", "fmul", "fdiv"}
        self.system_instructions = {"int", "hlt"}
        self.other_instructions = set()  # To capture any instructions not categorized above

    def start(self):
        try:
            self.dbg.run()
            print("Debugger started.")
        except Exception as e:
            print(f"Error starting debugger: {e}")
            traceback.print_exc()
            sys.exit(1)

    # Reading data from binary file and store it inside self.binary_data
    def read_binary_file(self):
        try:
            with open(self.binary_path , 'rb') as binary_file:
                self.binary_data = binary_file.read()
        except Exception as e:
            print(f"Error reading: {e}")
            
        start_address=0x100000
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        instructions = md.disasm(self.binary_data, start_address)
        
        for i in instructions:
            self.data.append(i.address)
            self.mnemonics.append(i.mnemonic)

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
            self.instruction_count += 1
            instruction_type = self.get_current_instruction_type()
            self.instruction_types.append(instruction_type)
            self.print_instruction_type(instruction_type)
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

    def read_memory(self, start_address=0x100000):
        
        address = self.data[self.idx].to_bytes(64, 'little')
        self.idx +=1    
        address = address*64
        return address

    def get_current_instruction_type(self):
        try:
            rip = self.get_instruction_pointer()
            code = self.read_memory()  # Using the read_memory method to fetch bytes from memory
            for insn in self.disassembler.disasm(code, rip):
                return insn.mnemonic
            return "Unknown"
        except Exception as e:
            print(f"Error getting current instruction type: {e}")
            traceback.print_exc()
            return "Unknown"

    def print_instruction_type(self, instruction_type):
        if instruction_type in self.data_movement_instructions:
            print(f"Instruction {self.instruction_count}: Data Movement - {instruction_type}")
        elif instruction_type in self.logical_instructions:
            print(f"Instruction {self.instruction_count}: Logical - {instruction_type}")
        elif instruction_type in self.control_flow_instructions:
            print(f"Instruction {self.instruction_count}: Control Flow - {instruction_type}")
        elif instruction_type in self.comparison_instructions:
            print(f"Instruction {self.instruction_count}: Comparison - {instruction_type}")
        elif instruction_type in self.stack_instructions:
            print(f"Instruction {self.instruction_count}: Stack - {instruction_type}")
        elif instruction_type in self.string_instructions:
            print(f"Instruction {self.instruction_count}: String - {instruction_type}")
        elif instruction_type in self.bit_manipulation_instructions:
            print(f"Instruction {self.instruction_count}: Bit Manipulation - {instruction_type}")
        elif instruction_type in self.floating_point_instructions:
            print(f"Instruction {self.instruction_count}: Floating Point - {instruction_type}")
        elif instruction_type in self.system_instructions:
            print(f"Instruction {self.instruction_count}: System - {instruction_type}")
        elif instruction_type in self.arithmetic_instructions:
            print(f"Instruction {self.instruction_count}: Arithmetic - {instruction_type}")
        else:
            self.other_instructions.add(instruction_type)
            print(f"Instruction {self.instruction_count}: Other - {instruction_type}")
    
    def get_instruction_info(self):

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
        
        for mnemonic in self.mnemonics:
            instruction_count += 1
            
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
        
        return instruction_count, instruction_types    
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
    binary_path = "/home/mohibriyaz/Documents/libdebug/examples/breakpoint/memory_test"  # Path of the binary file
    debugger_instance = BreakPointDebugger(binary_path)
    debugger_instance.read_binary_file() 
    
    try:
        debugger_instance.start()
        debugger_instance.set_breakpoint("validate_setter")
        

        execution_counts = []
        timestamps = []
        instruction_times = []
        start_time = time.time()
        
        max_steps = 25  # Maximum number of steps to prevent infinite loop
        summary_interval = 5  # Interval at which to print the summary of instructions
        last_instruction_pointer = None
        repeated_instruction_count = 0

        while True:
            step_start_time = time.time()
            debugger_instance.step()
            step_end_time = time.time()

            execution_counts.append(debugger_instance.get_instruction_count())
            timestamps.append(time.time() - start_time)
            instruction_times.append(step_end_time - step_start_time)

            current_instruction_pointer = debugger_instance.get_instruction_pointer()
            if current_instruction_pointer == last_instruction_pointer:
                repeated_instruction_count += 1
            else:
                repeated_instruction_count = 0

            last_instruction_pointer = current_instruction_pointer

            if repeated_instruction_count > 100:
                print("Detected possible infinite loop with repeated instructions. Exiting.")
                break

            if debugger_instance.get_instruction_count() > max_steps:
                print("Exceeded maximum step count. Exiting.")
                break

            if current_instruction_pointer == debugger_instance.bp_address:
                print("Reached breakpoint address. Exiting.")
                break

            if debugger_instance.get_instruction_count() % summary_interval == 0:
                unique_instruction_types, instruction_counts = np.unique(debugger_instance.get_instruction_types(), return_counts=True)
                instruction_summary = dict(zip(unique_instruction_types, instruction_counts))
                print(f"Intermediate summary at step {debugger_instance.get_instruction_count()}: {instruction_summary}")

        print(f"Number of instructions executed until breakpoint: {debugger_instance.get_instruction_count()}")
        print(f"Instruction pointer (RIP) at breakpoint: {hex(debugger_instance.get_instruction_pointer())}")
        instruction_types = debugger_instance.get_instruction_types()
        unique_instruction_types, instruction_counts = np.unique(instruction_types, return_counts=True)
        instruction_summary = dict(zip(unique_instruction_types, instruction_counts))
        print(f"Summary of instruction types executed: {instruction_summary}")

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

    instruction_count, instruction_types = debugger_instance.get_instruction_info()

    plot_combined(instruction_count, instruction_types)

    
    plt.figure(figsize=(14, 7))
    plt.plot(timestamps, execution_counts, label='Total Instructions Executed', color='green', marker='o', linestyle='-')
    plt.xlabel('Time in (seconds)', fontsize=14)
    plt.ylabel('Number of Instructions Executed', fontsize=14)
    plt.title('Number of Instructions Executed on Binary Over Time', fontsize=11)
    plt.grid(True, linestyle='--', alpha=0.2)

    max_instructions = max(execution_counts)
    max_time = timestamps[execution_counts.index(max_instructions)]
    plt.annotate(f'Max: {max_instructions} instructions',
                 xy=(max_time, max_instructions),
                 xytext=(max_time + (max_time * 0.1), max_instructions + (max_instructions * 0.1)),
                 arrowprops=dict(facecolor='black', arrowstyle='->'),
                 fontsize=12, color='black')

    plt.legend(fontsize=12)
    plt.gca().set_facecolor('#f7f7f7')
    plt.tight_layout()

    output_dir = '/home/mohibriyaz/Downloads/libdebug-main/examples/breakpoint'
    os.makedirs(output_dir, exist_ok=True)

    output_path = os.path.join(output_dir, 'line_graph.png')
    plt.savefig(output_path)
    plt.show()
    # Plotting execution time per instruction type
    # Aggregate times by instruction type
    time_by_type = {}
    for type, time in zip(debugger_instance.mnemonics, instruction_times):
        if type in time_by_type:
            time_by_type[type] += time
        else:
            time_by_type[type] = time
    labels = list(time_by_type.keys())
    sizes = list(time_by_type.values())
    colors = plt.cm.tab20(np.linspace(0, 1, len(labels)))  # Generate distinct colors

    plt.figure(figsize=(12, 8))
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.axis('equal') 
    execution_time_output_path = os.path.join(output_dir, 'execution_time.png')
    plt.savefig(execution_time_output_path)
    plt.show()



    

    