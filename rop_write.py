import subprocess
import sys
import re
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86_const import X86_OP_REG, X86_OP_MEM, X86_OP_IMM, X86_OP_INVALID
import r2pipe


def split_out_gadget_addresses(gadget_list):
    gadgets = re.split(rb'\nGadget: 0x\w*\n', gadget_list)
    gadget_addresses = [None] * len(gadgets)
    for index, gadget in enumerate(gadgets):
        instructions = gadget.split(b'\n')
        gadget_addresses[index] = [instruction.split(b':')[0] for instruction in instructions if instruction != b'']
    gadget_addresses.pop(0)
    return gadget_addresses


def get_gadgets_with_ropper(binary):
    # TODO: split gadgets on ';' for individual instructions
    # TODO: discard instructions that aren't what we're looking for
    ropper_command_base = ["ropper", "-f", binary, "--nocolor", "--detailed", "--search"]
    pop_ropper_command = [*ropper_command_base, "pop"]
    mov_ropper_command = [*ropper_command_base, "mov"]

    pop_return = subprocess.run(pop_ropper_command, capture_output=True)
    pop_gadget_addresses = split_out_gadget_addresses(pop_return.stdout)

    mov_return = subprocess.run(mov_ropper_command, capture_output=True)
    mov_gadget_addresses = split_out_gadget_addresses(mov_return.stdout)
    print("mov_gadget_addresses: " + str(mov_gadget_addresses))
    print("as a string: " + mov_gadget_addresses[0][0].decode())

    # remove leading None element
    return pop_gadget_addresses, mov_gadget_addresses


def prepare_instruction_for_capstone(instruction_address, instruction_bytes):
    stripped_instruction_bytes = instruction_bytes.removeprefix('bytes: ').removesuffix('\n')
    print('address: ' + instruction_address.decode() + ', bytes: ' + stripped_instruction_bytes)
    individual_instruction_bytes = b''
    character_set = ''
    for index in range(len(stripped_instruction_bytes)):
        print('index: ' + str(index) + ' character: ' + str(stripped_instruction_bytes[index]))
        character_set += stripped_instruction_bytes[index]
        if index % 2 == 1:
            individual_instruction_bytes = bytes.fromhex(character_set)

    print("individual_instruction_bytes: " + str(individual_instruction_bytes))
    return individual_instruction_bytes


def get_instruction_details(gadget):
    instruction_bytes = b''
    for instruction_address in gadget:
        instruction_byte_string = r2.cmd('s ' + str(instruction_address.decode()) + '; ao ~bytes: ')
        instruction_bytes += prepare_instruction_for_capstone(instruction_address, instruction_byte_string)

    instruction_details = disassembler.disasm(instruction_bytes, int(gadget[0], 16))
    return instruction_details


def create_list_of_viable_mov_gadgets(mov_gadget_details):
    ...
    # create 2 dicts of instruction addresses:

    # mov instructions: contents of one register to the address in another WITHOUT shifts
    # mov instructions: contents of one register to the address in another WITH shifts,

def find_best_gadgets(pop_gadget_addresses, mov_gadget_addresses):
    for mov_gadget_address in mov_gadget_addresses:
        mov_gadget_details = get_instruction_details(mov_gadget_address)



def create_write_rop_chain(binary, string='abc', memory_location='0x0'):
    # get possible gadgets with ropper
    pop_gadget_addresses, mov_gadget_addresses = get_gadgets_with_ropper(binary)

    # find a 'mov [y], x' where both x and y can be popped to
    # for chain in pop_return
    find_best_gadgets(pop_gadget_addresses, mov_gadget_addresses)

    # build chain

    #   get memory addresses of gadgets

    #   format

def init_capstone():
    cs_disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    cs_disassembler.detail = True
    return cs_disassembler

if __name__ == '__main__':
    binary_arg = sys.argv[1]
    disassembler = init_capstone()
    r2 = r2pipe.open(binary_arg)
    # string = sys.argv[1]
    # memory_location = sys.argv[2]
    create_write_rop_chain(binary_arg)
