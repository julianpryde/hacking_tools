import locale
from subprocess import run
from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsInsn
from capstone.x86_const import X86_OP_REG, X86_OP_MEM
import r2pipe
from typing import Sized, Iterable, List, SupportsIndex, AnyStr, Tuple, ByteString, Callable
from ctypes import ArgumentError
from pwn import *
from sys import argv
from re import split
from struct import calcsize


class RegisterError(Exception):
    def __init__(self):
        self.msg = "Operand does not operate on a register"


class GadgetWrapper(List[CsInsn], Iterable):
    def __init__(self, gadget: List[CsInsn]):
        super().__init__()
        self.instruction_list: List[CsInsn] = gadget
        self.useful_instruction_index_in_gadget: List[int | SupportsIndex] | None = None

    def set_useful_instruction_index(self, index: List[SupportsIndex]):
        self.useful_instruction_index_in_gadget = index

    def __getitem__(self, index: SupportsIndex) -> CsInsn:
        return self.instruction_list[index]

    def __iter__(self):
        return iter(self.instruction_list)


class WriteGadgetWrapper(GadgetWrapper):
    def __init__(self, gadget: List[CsInsn]):
        super().__init__(gadget)
        self.steps_to_return: int = 0

    def reset_steps_to_return(self):
        self.steps_to_return = 0

    def increment_steps_to_return(self):
        self.steps_to_return += 1


class PopGadgetWrapper(GadgetWrapper):
    def __init__(self, gadget: List[CsInsn],
                 garbage: List | None = None,
                 garbage_counter_array_position: SupportsIndex = 0
                 ):
        super().__init__(gadget)
        self.garbage: List = garbage
        self.garbage_counter_array_position = garbage_counter_array_position
        self.initialize_garbage()
        self.num_useful_pops_in_this_gadget = 0

    def initialize_garbage(self):
        self.garbage = [0, 0, 0]

    def increment_garbage(self):
        self.garbage[self.garbage_counter_array_position] += 1

    def increment_garbage_counter_array_position(self):
        self.garbage_counter_array_position += 1

    def increment_num_useful_pops_in_this_gadget(self):
        self.num_useful_pops_in_this_gadget += 1


class RopChain:
    def __init__(self):
        self.valid = False

    def validate(self) -> None: ...

    def format(self, string_to_write: AnyStr, address: int) -> ByteString: ...


class WriteRopChain(RopChain):
    def __init__(self):
        super().__init__()
        self.write_gadget: WriteGadgetWrapper | None = None
        self.src_pop_gadget: PopGadgetWrapper | None = None
        self.dest_pop_gadget: PopGadgetWrapper | None = None
        self.number_of_pop_gadgets = 2

    def set_write_gadget(self, write_gadget: WriteGadgetWrapper):
        self.write_gadget = write_gadget

    def set_src_gadget(self, src_pop_gadget: PopGadgetWrapper):
        self.src_pop_gadget = src_pop_gadget

    def set_dest_gadget(self, dest_pop_gadget: PopGadgetWrapper):
        self.dest_pop_gadget = dest_pop_gadget

    def validate(self):
        self.valid = True if self.src_pop_gadget is not None and self.dest_pop_gadget is not None else False

    def split_str(self, string_to_write: AnyStr) -> List[ByteString]:
        os_size_bytes = calcsize("P")
        bytes_to_write = string_to_write.encode()
        return [bytes_to_write[i:i+os_size_bytes] for i in range(0, len(bytes_to_write), os_size_bytes)]

    def format(self, string_to_write: AnyStr, address: int) -> ByteString:
        rop_chain = b''
        src_is_first = lambda : True if \
            self.src_pop_gadget.useful_instruction_index_in_gadget < \
            self.dest_pop_gadget.useful_instruction_index_in_gadget \
            else False
        for byte_string in self.split_str(string_to_write):
            rop_chain += byte_string if src_is_first else pack(address)
            rop_chain += pack(address) if not src_is_first else pack(address)
            for i in range(self.number_of_pop_gadgets):
                rop_chain += pack(self.)
        return rop_chain


class SortedRopChainBuffer(Sized, Iterable):
    def __init__(self, num_elements: int = 0):
        super().__init__()
        self.chains: List[RopChain] | List[None] = [None] * num_elements

    def __getitem__(self, index: SupportsIndex) -> RopChain:
        return self.chains[index]

    def __setitem__(self, index: SupportsIndex, value: RopChain):
        self.chains[index] = value

    def __len__(self):
        return len(self.chains)

    def __iter__(self):
        return iter(self.chains)

    def _insert(self, rop_chain: RopChain, index: SupportsIndex):
        self[index] = rop_chain
        self._sort()

    @staticmethod
    def _key_getter(gadget: GadgetWrapper) -> Tuple[SupportsIndex, int]: ...

    def push(self, chain: RopChain) -> None: ...

    def _sort(self): ...

    # def to_string(self) -> AnyStr: ...


class SortedWriteChainsBuffer(SortedRopChainBuffer):
    def __init__(self, num_elements):
        super().__init__()
        self.chains: List[WriteRopChain] | List[None] = [None] * num_elements

    @staticmethod
    def _key_getter(chain: WriteRopChain) -> Tuple[int, int]:
        return chain.number_of_pop_gadgets, chain.write_gadget.steps_to_return

    def get_last_chain_write_gadget_steps_to_return(self) -> int:
        return self.chains[-1].write_gadget.steps_to_return

    def push(self, new_chain: WriteRopChain) -> None:
        # if not all slots are taken, push on to the end of the list
        for index, value in enumerate(self):
            if value is None:
                self._insert(new_chain, index)
                return
        # if new chain uses fewer pop gadgets than the existing lowest number of pop gadgets, use it, else attrite it
        if new_chain.number_of_pop_gadgets < self.chains[-1].number_of_pop_gadgets:
            self._insert(new_chain, -1)
        # if new chain uses more pop gadgets than existing lowest number of pop gadgets, attrite it
        elif new_chain.number_of_pop_gadgets > self.chains[-1].number_of_pop_gadgets:
            return
        # if new chain uses same number of pop gadgets:
        # if new chain uses same number of pop gadgets than existing but fewer instructions to return from mov, use it
        elif new_chain.number_of_pop_gadgets == self.chains[-1].number_of_pop_gadgets:
            if new_chain.write_gadget.steps_to_return <= self.chains[-1].write_gadget.steps_to_return:
                self._insert(new_chain, -1)
            else:
                return  # else, attrite

    def _sort(self):
        gadgets_to_sort = [value for value in self if value is not None]
        sorted_gadgets = sorted(gadgets_to_sort, key=self._key_getter)
        for index, gadget in enumerate(sorted_gadgets):
            self[index] = sorted_gadgets[index]


def split_out_gadget_addresses(gadget_list: AnyStr) -> List[AnyStr]:
    gadgets = split(r'\nGadget: 0x\w*\n', gadget_list)
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


def get_gadget_details(gadget_addresses: List[AnyStr]) -> Iterable[List[CsInsn]]:
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
        if instruction.mnemonic == 'pop':
            return instruction.reg_name(instruction.operands[0].reg)
        elif instruction.mnemonic == 'mov':
            return instruction.reg_name(instruction.regs_access()[0][0 if action == 'read' else 1])
    except IndexError:
        print(instruction.op_str + ' does not ' + action + ' any registers')
        raise RegisterError
    except ArgumentError:
        print('what?')
        raise


def add_pop_gadget_to_chain(pop_gadget: PopGadgetWrapper,
                            set_gadget_in_chain: Callable[[PopGadgetWrapper], None]
                            ) -> None:
    set_gadget_in_chain(pop_gadget)
    pop_gadget.increment_garbage_counter_array_position()
    pop_gadget.increment_num_useful_pops_in_this_gadget()


def attrite_write_gadgets(write_src_register: AnyStr,
                          write_dest_register: AnyStr,
                          pop_gadget_addresses: List[AnyStr],
                          write_chain: WriteRopChain) -> WriteRopChain:
    for gadget_instruction_list in get_gadget_details(pop_gadget_addresses):
        pop_gadget = PopGadgetWrapper(gadget_instruction_list)
        for pop_instruction_index, pop_instruction in enumerate(pop_gadget):
            if pop_instruction.mnemonic == 'pop':
                pop_register = get_register(pop_instruction, 'write')
                if pop_register == write_src_register:
                    add_pop_gadget_to_chain(pop_gadget, write_chain.set_src_gadget)
                elif pop_register == write_dest_register:
                    add_pop_gadget_to_chain(pop_gadget, write_chain.set_dest_gadget)
                else:
                    # if more pops are found, save amount of garbage needed to deal with instructions in the gadget
                    pop_gadget.increment_garbage()
        if write_chain.src_pop_gadget is write_chain.dest_pop_gadget is not None:
            write_chain.number_of_pop_gadgets = 1
            break  #  if both instructions are from the same gadget, return immediately and record.
    write_chain.validate()
    return write_chain


def find_best_write_gadget(mov_gadgets_details: Iterable[List[CsInsn]], pop_gadget_addresses: List[AnyStr])\
        -> SortedWriteChainsBuffer:
    best_rop_chains = SortedWriteChainsBuffer(5)
    for mov_gadget in mov_gadgets_details:
        write_chain = WriteRopChain()
        write_chain.write_gadget = WriteGadgetWrapper(mov_gadget)
        for mov_instruction_index, mov_instruction in enumerate(mov_gadget):
            if mov_instruction.mnemonic == 'mov':
                if mov_instruction.operands[0].type == X86_OP_MEM and mov_instruction.operands[1].type == X86_OP_REG:
                    write_chain = attrite_write_gadgets(
                        get_register(mov_instruction, 'read'),
                        get_register(mov_instruction, 'write'),
                        pop_gadget_addresses,
                        write_chain)
                    if write_chain.valid:
                        write_chain.write_gadget.reset_steps_to_return()
                        write_chain.write_gadget.set_useful_instruction_index([mov_instruction_index])
            write_chain.write_gadget.increment_steps_to_return()
        if write_chain.valid:
            best_rop_chains.push(write_chain)

    return best_rop_chains


def create_write_rop_chain(binary: AnyStr, string: AnyStr = 'abc', memory_location: int ='0x0'):
    # get possible gadgets with ropper
    mov_gadget_addresses = get_gadgets_with_ropper(binary, 'mov')
    pop_gadget_addresses = get_gadgets_with_ropper(binary, 'pop')

    # get gadget details
    mov_gadgets_details = get_gadget_details(mov_gadget_addresses)

    # find a 'mov [y], x' where both x and y can be popped to for chain in pop_return
    best_write_gadgets = find_best_write_gadget(mov_gadgets_details, pop_gadget_addresses)

    #   format
    best_write_gadgets[0].format(string, memory_location)

def init_capstone() -> Cs:
    cs_disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    cs_disassembler.detail = True
    return cs_disassembler

if __name__ == '__main__':
    binary_arg = argv[1]
    disassembler = init_capstone()
    r2 = r2pipe.open(binary_arg)
    # string = sys.argv[1]
    # memory_location = sys.argv[2]
    create_write_rop_chain(binary_arg)
