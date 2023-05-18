import locale
from subprocess import run
import sys
import re
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86_const import X86_OP_REG, X86_OP_MEM, X86_OP_IMM
import r2pipe
from typing import Sized, Iterable
from operator import itemgetter


class SortedWriteGadgetBuffer(Sized, Iterable):
    def __init__(self, size=0):
        super().__init__()
        self.gadgets = [None] * size

    def __getitem__(self, index):
        return self.gadgets[index]

    def __setitem__(self, index, value):
        self.gadgets[index] = value

    def __len__(self):
        return len(self.gadgets)

    def __iter__(self):
        return iter(self.gadgets)

    def _insert(self, steps_to_return, gadget, index, inst_index_in_gadget):
        self[index] = (steps_to_return, gadget[inst_index_in_gadget].operands[0].mem.disp, gadget)

    def _attrite(self, steps_to_ret, gadget, inst_index_in_gadget):
        # if not all slots are taken, push on to the end of the list
        for index, value in enumerate(self):
            if value is None:
                self._insert(steps_to_ret, gadget, index, inst_index_in_gadget)
                return

        if steps_to_ret < self[-1][0]:
            self._insert(steps_to_ret, gadget, -1, inst_index_in_gadget)
        elif steps_to_ret == self[-1][0] and gadget[inst_index_in_gadget].operands[0].mem.disp < self[-1][1]:
            self._insert(steps_to_ret, gadget, -1, inst_index_in_gadget)
        elif steps_to_ret > self[-1][0]:
            return

    def sort(self):
        gadgets_to_sort = [value for value in self if value is not None]
        sorted_gadgets = sorted(gadgets_to_sort, key=itemgetter(0, 1))
        for index, gadget in enumerate(sorted_gadgets):
            self[index] = sorted_gadgets[index]

    def push(self, steps_to_ret, gadget, index):
        """
        appends the gadget to the list if it has a lower steps_to_ret than the lowest in the list. If it has the same
        steps_to_ret as at least one in the list, it adds it if it has a lower displacement than the highest in the list
        """
        self._attrite(steps_to_ret, gadget, index)
        self.sort()

    def to_string(self):
        return str(self.gadgets)

def split_out_gadget_addresses(gadget_list):
    gadgets = re.split(r'\nGadget: 0x\w*\n', gadget_list)
    gadgets.pop(0)  # remove leading empty string
    gadget_addresses = [None] * len(gadgets)
    for index, gadget in enumerate(gadgets):
        instructions = gadget.split('\n')
        gadget_addresses[index] = [instruction.split(':')[0] for instruction in instructions if instruction != '']
    return gadget_addresses


def get_gadgets_with_ropper(binary, keyword):
    """
    Writes to buffer "gadget_stream" for create_list_of_viable_mov_gadgets() to read from concurrently
    """
    ropper_command_base = ["ropper", "-f", binary, "--nocolor", "--detailed", "--search"]
    ropper_command = [*ropper_command_base, keyword]

    ropper_output = run(ropper_command, capture_output=True, encoding=locale.getpreferredencoding())
    gadget_addresses = split_out_gadget_addresses(ropper_output.stdout)

    return gadget_addresses


def prepare_instruction_for_capstone(instruction_bytes):
    stripped_instruction_bytes = instruction_bytes.removeprefix('bytes: ').removesuffix('\n')
    individual_instruction_bytes = b''
    character_set = ''
    for index in range(len(stripped_instruction_bytes)):
        character_set += stripped_instruction_bytes[index]
        if index % 2 == 1:
            individual_instruction_bytes = bytes.fromhex(character_set)

    return individual_instruction_bytes


def get_gadget_details(gadget_addresses):
    """
    The list of instructions in a gadget are probably going to be very small but the list of gadgets could be very large
    => this function returns a single gadget at a time, each with a list of instruction details in the format given by
    capstone.
    """
    for gadget_address in gadget_addresses:
        instruction_bytes = b''
        for instruction_address in gadget_address:
            instruction_byte_string = r2.cmd('s ' + str(instruction_address) + '; ao ~bytes: ')
            instruction_bytes += prepare_instruction_for_capstone(instruction_byte_string)

        gadget_details = list(disassembler.disasm(instruction_bytes, int(gadget_address[0], 16)))
        yield gadget_details


def get_capstone_register(operand, instruction):
    if operand.type == X86_OP_REG:
        return instruction.reg_name(operand.reg)
    elif operand.type == X86_OP_IMM:
        return hex(operand.imm)
    elif operand.type == X86_OP_MEM:
        if operand.mem.segment != 0:
            return instruction.reg_name(operand.mem.segment)
        elif operand.mem.base != 0:
            return instruction.reg_name(operand.mem.base)
        elif operand.mem.index != 0:
            return instruction.reg_name(operand.mem.index)


def attrite_write_gadgets(write_instruction, pop_gadget_addresses):
    for gadget in get_gadget_details(pop_gadget_addresses):
        for instruction in gadget:
            ...
            # if 'pop to' register matches either source or destination register, save pop gadget
                # note instructions before and after...
            # if a gadget is found that matches the other register, save it
            # if pop gadgets are found that pop to both registers in the source register, save it and amount of garbage
            # needed to deal with instructions in the gadget


def find_best_write_gadget(mov_gadgets_details, pop_gadget_addresses):
    """
    mov_gadgets_details is a generator of lists of instructions
    creates a list of most preferred mov gadgets by number of steps from 'mov' to 'ret' => minimize chance for other
    things to mess up the memory write
    """
    best_gadgets = SortedWriteGadgetBuffer(5)
    for gadget in mov_gadgets_details:
        steps_to_ret = 0
        write_index = 0
        for index, instruction in enumerate(gadget):
            if instruction.mnemonic == 'mov':
                if instruction.operands[0].type == X86_OP_MEM:
                    attrite_write_gadgets(instruction, pop_gadget_addresses)
                    steps_to_ret = 0
                    write_index = index
            steps_to_ret += 1

        best_gadgets.push(steps_to_ret, gadget, write_index)

    return best_gadgets


def create_write_rop_chain(binary, string='abc', memory_location='0x0'):
    # get possible gadgets with ropper
    mov_gadget_addresses = get_gadgets_with_ropper(binary, 'mov')
    pop_gadget_addresses = get_gadgets_with_ropper(binary, 'pop')

    # get gadget details
    mov_gadgets_details = get_gadget_details(mov_gadget_addresses)

    # find a 'mov [y], x' where both x and y can be popped to
    # for chain in pop_return
    best_write_gadgets = find_best_write_gadget(mov_gadgets_details, pop_gadget_addresses)
    print(best_write_gadgets.to_string())

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
