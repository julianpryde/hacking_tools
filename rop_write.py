import locale
from subprocess import run
import sys
import re
from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsInsn
from capstone.x86_const import X86_OP_REG, X86_OP_MEM
import r2pipe
from typing import Sized, Iterable, List, SupportsIndex, AnyStr, Tuple, ByteString, Generator
from ctypes import ArgumentError
from pwn import *


class RegisterError(Exception):
    def __init__(self):
        self.msg = "Operand does not operate on a register"


class GadgetWrapper(List[CsInsn]):
    def __init__(self, gadget: List[CsInsn]):
        super().__init__()
        self.gadget_list: List[CsInsn] = gadget
        self.useful_instruction_index_in_gadget: List[SupportsIndex] | None = None

    def set_useful_instruction_index(self, index: List[SupportsIndex]):
        self.useful_instruction_index_in_gadget = index

    def __getitem__(self, index: SupportsIndex) -> CsInsn:
        return self.gadget_list[index]


class WriteGadgetWrapper(GadgetWrapper):
    def __init__(self, gadget: List[CsInsn], steps_to_return: SupportsIndex | None = None):
        super().__init__(gadget)
        self.steps_to_return: SupportsIndex | None = steps_to_return

    def set_steps_to_return(self, steps_to_return: SupportsIndex):
        self.steps_to_return = steps_to_return


class PopGadgetWrapper(GadgetWrapper):
    def __init__(self, gadget: List[CsInsn], garbage: List | None = None):
        super().__init__(gadget)
        self.garbage: List = garbage

    def set_garbage(self, garbage: List):
        self.garbage = garbage

    def increment_garbage(self, index: SupportsIndex):
        try:
            self.garbage[index] += 1
        except TypeError:
            print('Garbage never initialized')
            raise


class GadgetBuffer(Sized, Iterable):
    def __init__(self, size=0):
        super().__init__()
        self.gadgets: List[GadgetWrapper] | List[None] = [None] * size

    def __getitem__(self, index: SupportsIndex) -> GadgetWrapper:
        return self.gadgets[index]

    def __setitem__(self, index: SupportsIndex, value: GadgetWrapper):
        self.gadgets[index] = value

    def __len__(self):
        return len(self.gadgets)

    def __iter__(self):
        return iter(self.gadgets)

    def _insert(self, gadget: GadgetWrapper, index: SupportsIndex):
        self[index] = gadget


class WriteChainGadgets:
    def __init__(self):
        self.write_gadget: WriteGadgetWrapper | None = None
        self.src_pop_gadget: PopGadgetWrapper | None = None
        self.dest_pop_gadget: PopGadgetWrapper | None = None

    def set_write_gadget(self, write_gadget: WriteGadgetWrapper):
        self.write_gadget = write_gadget

    def set_src_gadget(self, src_pop_gadget: PopGadgetWrapper):
        self.src_pop_gadget = src_pop_gadget

    def set_dest_gadget(self, dest_pop_gadget: PopGadgetWrapper):
        self.dest_pop_gadget = dest_pop_gadget


class SortedWriteGadgetBuffer(GadgetBuffer):
    @staticmethod
    def _key_getter(gadget: WriteGadgetWrapper) -> Tuple[SupportsIndex, int]:
        return gadget.steps_to_return, gadget[gadget.useful_instruction_index_in_gadget[0]].operands[0].mem.disp

    def _attrite(self, steps_to_ret: SupportsIndex, gadget: WriteGadgetWrapper, inst_index_in_gadget: SupportsIndex)\
            -> None:
        # if not all slots are taken, push on to the end of the list
        for index, value in enumerate(self):
            if value is None:
                self._insert(gadget, index)
                return

        if steps_to_ret < self[-1].useful_instruction_index_in_gadget[0]:
            self._insert(gadget, -1)
        elif steps_to_ret == self[-1][0] and gadget[inst_index_in_gadget].operands[0].mem.disp < self[-1][1]:
            self._insert(gadget, -1)
        elif steps_to_ret > self[-1].useful_instruction_index_in_gadget[0]:
            return

    def _sort(self):
        gadgets_to_sort = [value for value in self if value is not None]
        sorted_gadgets = sorted(gadgets_to_sort, key=self._key_getter)
        for index, gadget in enumerate(sorted_gadgets):
            self[index] = sorted_gadgets[index]

    def push(self, steps_to_ret: SupportsIndex, gadget: WriteGadgetWrapper, index: SupportsIndex):
        """
        appends the gadget to the list if it has a lower steps_to_ret than the lowest in the list. If it has the same
        steps_to_ret as at least one in the list, it adds it if it has a lower displacement than the highest in the list
        """
        self._attrite(steps_to_ret, gadget, index)
        self._sort()

    def to_string(self) -> AnyStr:
        return str(self.gadgets)

def split_out_gadget_addresses(gadget_list: AnyStr) -> List[AnyStr]:
    gadgets = re.split(r'\nGadget: 0x\w*\n', gadget_list)
    gadgets.pop(0)  # remove leading empty string
    gadget_addresses = [''] * len(gadgets)
    for index, gadget in enumerate(gadgets):
        instructions = gadget.split('\n')
        gadget_addresses[index] = [instruction.split(':')[0] for instruction in instructions if instruction != '']
    return gadget_addresses


def get_gadgets_with_ropper(binary: AnyStr, keyword: AnyStr) -> List[AnyStr]:
    """
    Writes to buffer "gadget_stream" for create_list_of_viable_mov_gadgets() to read from concurrently
    """
    ropper_command_base = ["ropper", "-f", binary, "--nocolor", "--detailed", "--search"]
    ropper_command = [*ropper_command_base, keyword]

    ropper_output = run(ropper_command, capture_output=True, encoding=locale.getpreferredencoding())
    gadget_addresses = split_out_gadget_addresses(ropper_output.stdout)

    return gadget_addresses


def prepare_instruction_for_capstone(instruction_bytes: AnyStr) -> ByteString:
    stripped_instruction_bytes = instruction_bytes.removeprefix('bytes: ').removesuffix('\n')
    individual_instruction_bytes = b''
    character_set = ''
    for index in range(len(stripped_instruction_bytes)):
        character_set += stripped_instruction_bytes[index]
        if index % 2 == 1:
            individual_instruction_bytes = bytes.fromhex(character_set)

    return individual_instruction_bytes


def get_gadget_details(gadget_addresses: List[AnyStr]) -> Generator[List[CsInsn]]:
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


def get_register(instruction: CsInsn, action: AnyStr) -> AnyStr:
    try:
        return instruction.reg_name(instruction.regs_access()[0 if action == 'read' else 1][0])
    except IndexError:
        print(instruction.op_str + ' does not ' + action + 'any registers')
        raise RegisterError
    except ArgumentError:
        print('what?')
        raise


def attrite_write_gadgets(write_src_register: AnyStr, write_dest_register: AnyStr, pop_gadget_addresses: List[AnyStr])\
        -> WriteChainGadgets:
    # each position in the array is number of garbage pops in before, between, and after the useful pops
    garbage_pop_counter = [0, 0, 0]
    gadget_pairs = {'src pop': None, 'dest pop': None, 'src garbage': None, 'dest garbage': None}
    garbage_pop_counter_array_position = 0
    for pop_gadget in get_gadget_details(pop_gadget_addresses):
        for pop_instruction_index, pop_instruction in enumerate(pop_gadget):
            if pop_instruction.mnemonic == 'pop':
                pop_register = get_register(pop_instruction, 'write')
                if pop_register == write_src_register:
                    gadget_pairs['src pop'] = pop_gadget
                    garbage_pop_counter_array_position += 1
                elif pop_register == write_dest_register:
                    gadget_pairs['dest pop'] = pop_gadget
                    garbage_pop_counter_array_position += 1
                else:
                    # if more pops are found, save amount of garbage needed to deal with instructions in the gadget
                    garbage_pop_counter[garbage_pop_counter_array_position] += 1
        if garbage_pop_counter_array_position == 2:  # if both pops are in the same instruction
            gadget_pairs.pop('src garbage')
            gadget_pairs.pop('dest garbage')
            gadget_pairs['garbage'] = garbage_pop_counter
        else:
            gadget_pairs['src garbage'] = garbage_pop_counter if gadget_pairs['src pop'] is not None else None
            gadget_pairs['dest garbage'] = garbage_pop_counter if gadget_pairs['dest pop'] is not None else None
        garbage_pop_counter = [0, 0, 0]
        garbage_pop_counter_array_position = 0


def find_best_write_gadget(mov_gadgets_details: Generator[List[CsInsn]], pop_gadget_addresses: List[AnyStr])\
        -> SortedWriteGadgetBuffer:
    """
    mov_gadgets_details is a generator of lists of instructions
    creates a list of most preferred mov gadgets by number of steps from 'mov' to 'ret' => minimize chance for other
    things to mess up the memory write
    """
    best_write_gadgets = SortedWriteGadgetBuffer(5)
    for mov_gadget in mov_gadgets_details:
        write_gadget_steps_to_ret = 0
        write_instruction_index = 0
        for mov_instruction_index, mov_instruction in enumerate(mov_gadget):
            if mov_instruction.mnemonic == 'mov':
                if mov_instruction.operands[0].type == X86_OP_MEM and mov_instruction.operands[1].type == X86_OP_REG:
                    write_src_register = get_register(mov_instruction, 'read')
                    write_dest_register = get_register(mov_instruction, 'write')
                    attrite_write_gadgets(write_src_register, write_dest_register, pop_gadget_addresses)
                    write_gadget_steps_to_ret = 0
                    write_instruction_index = mov_instruction_index
            write_gadget_steps_to_ret += 1

        write_gadget = WriteGadgetWrapper(mov_gadget, write_gadget_steps_to_ret)
        best_write_gadgets.push(write_gadget_steps_to_ret, write_gadget, write_instruction_index)

    return best_write_gadgets


def create_write_rop_chain(binary: AnyStr, string: AnyStr = 'abc', memory_location: int ='0x0') -> :
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
