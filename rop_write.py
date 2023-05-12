import subprocess
import sys
import re
import r2pipe


def get_gadget_address(gadget_bytes):
    gadget_address = gadget_bytes.split(b':')[0]
    try:
        int_address = int(gadget_address.decode(), 16)
    except ValueError:
        return None

    return int_address


def get_gadgets_with_ropper(binary):
    ropper_command_base = ["ropper", "-f", binary, "--nocolor", "--search"]
    pop_ropper_command = [*ropper_command_base, "pop"]
    mov_ropper_command = [*ropper_command_base, "mov"]

    pop_return = subprocess.run(pop_ropper_command, capture_output=True)
    pop_gadgets = pop_return.stdout.split(b'\n')

    mov_return = subprocess.run(mov_ropper_command, capture_output=True)
    mov_gadgets = mov_return.stdout.split(b'\n')

    pop_gadget_addresses = [get_gadget_address(pop_gadget) for pop_gadget in pop_gadgets]
    mov_gadget_addresses = [get_gadget_address(mov_gadget) for mov_gadget in mov_gadgets]

    # remove leading None element
    return pop_gadget_addresses[1:], mov_gadget_addresses[1:]


def get_instruction_at_address(address):
    disasm_instruction = r2.cmd('s ' + str(address) + '; ao 1 ~disasm')
    disasm_instruction_list = disasm_instruction.split(" ")
    return disasm_instruction_list


def get_mov_registers(address):
    disasm_instruction_list = get_instruction_at_address(address)
    src_register = disasm_instruction_list[-1][:-1]  # remove trailing '\n' from last instruction
    dest_register = disasm_instruction_list[-2]
    dest_register = dest_register[:-1]  # remove trailing ',' from first instruction

    return src_register, dest_register


def get_pop_register(address):
    disasm_instruction_list = get_instruction_at_address(address)
    pop_register =


def find_best_gadgets(pop_gadget_addresses, mov_gadget_addresses):
    for mov_gadget_address in mov_gadget_addresses:
        src_register, mov_dest_register = get_mov_registers(mov_gadget_address)
        print("\nsrc: " + src_register + "\ndest: " + mov_dest_register)
        match = re.search('\[(\w*)]', mov_dest_register)
        if match:
            for pop_gadget_address in pop_gadget_addresses:
                pop_dest_register = get_pop_register(pop_gadget_address)


def create_write_rop_chain(binary, string='abc', memory_location='0x0'):
    # get possible gadgets with ropper
    pop_gadget_addresses, mov_gadget_addresses = get_gadgets_with_ropper(binary)

    # find a 'mov [y], x' where both x and y can be popped to
    # for chain in pop_return
    find_best_gadgets(pop_gadget_addresses, mov_gadget_addresses)

    # build chain

    #   get memory addresses of gadgets

    #   format

if __name__ == '__main__':
    binary_arg = sys.argv[1]
    # string = sys.argv[1]
    # memory_location = sys.argv[2]
    r2 = r2pipe.open(binary_arg)
    create_write_rop_chain(binary_arg)
