"""Disassembly helper for x64 instruction analysis.

Uses Capstone disassembly engine to analyze instructions for data flow tracing.
"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, Tuple, List

# Try to import capstone, gracefully degrade if not available
try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
    from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    capstone = None


class InstructionCategory(Enum):
    """Categories of instructions for data flow analysis."""
    MOV_REG_REG = auto()      # mov reg, reg - register to register
    MOV_REG_MEM = auto()      # mov reg, [mem] - memory to register
    MOV_REG_IMM = auto()      # mov reg, imm - immediate to register
    MOV_MEM_REG = auto()      # mov [mem], reg - register to memory
    MOV_MEM_IMM = auto()      # mov [mem], imm - immediate to memory
    LEA = auto()              # lea reg, [mem] - load effective address
    PUSH = auto()             # push - stack push
    POP = auto()              # pop - stack pop
    CALL = auto()             # call - function call
    RET = auto()              # ret - function return
    ARITHMETIC = auto()       # add, sub, xor, etc. - arithmetic/logical
    MUL_DIV = auto()          # mul, div, imul, idiv - multiply/divide
    SHIFT = auto()            # shl, shr, sar, rol, ror - shift/rotate
    CMP_TEST = auto()         # cmp, test - comparison (no dest modification)
    XCHG = auto()             # xchg - exchange
    CMOV = auto()             # cmovcc - conditional move
    MOVZX_MOVSX = auto()      # movzx, movsx - zero/sign extend
    STRING_OP = auto()        # movs, stos, etc. - string operations
    UNKNOWN = auto()          # unrecognized instruction


@dataclass
class MemoryOperand:
    """Represents a memory operand in an instruction."""
    base_reg: Optional[str] = None    # Base register (e.g., "rax")
    index_reg: Optional[str] = None   # Index register (e.g., "rcx")
    scale: int = 1                     # Scale for index
    disp: int = 0                      # Displacement
    segment: Optional[str] = None     # Segment override

    def __str__(self) -> str:
        parts = []
        if self.segment:
            parts.append(f"{self.segment}:")
        parts.append("[")
        addr_parts = []
        if self.base_reg:
            addr_parts.append(self.base_reg)
        if self.index_reg:
            if self.scale > 1:
                addr_parts.append(f"{self.index_reg}*{self.scale}")
            else:
                addr_parts.append(self.index_reg)
        if self.disp != 0:
            if self.disp > 0 and addr_parts:
                addr_parts.append(f"+0x{self.disp:x}")
            elif self.disp < 0:
                addr_parts.append(f"-0x{-self.disp:x}")
            else:
                addr_parts.append(f"0x{self.disp:x}")
        parts.append(" + ".join(addr_parts) if addr_parts else "0")
        parts.append("]")
        return "".join(parts)


@dataclass
class DisassembledInstruction:
    """Represents a disassembled instruction with analysis info."""
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes_hex: str
    category: InstructionCategory
    dest_reg: Optional[str] = None           # Destination register if applicable
    source_reg: Optional[str] = None         # Source register if applicable
    source_mem: Optional[MemoryOperand] = None  # Source memory operand
    dest_mem: Optional[MemoryOperand] = None    # Destination memory operand
    immediate: Optional[int] = None          # Immediate value if applicable

    def __str__(self) -> str:
        return f"0x{self.address:x}: {self.mnemonic} {self.op_str}"


# x64 register name mappings (Capstone register IDs to names)
# These will be populated when Capstone is available
REG_NAME_MAP = {}

# Register aliasing - map 32/16/8-bit registers to their 64-bit parent
REG_ALIAS_TO_64 = {
    # 32-bit -> 64-bit
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
    "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
    "r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15",
    # 16-bit -> 64-bit
    "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
    "si": "rsi", "di": "rdi", "bp": "rbp", "sp": "rsp",
    "r8w": "r8", "r9w": "r9", "r10w": "r10", "r11w": "r11",
    "r12w": "r12", "r13w": "r13", "r14w": "r14", "r15w": "r15",
    # 8-bit -> 64-bit
    "al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx",
    "ah": "rax", "bh": "rbx", "ch": "rcx", "dh": "rdx",
    "sil": "rsi", "dil": "rdi", "bpl": "rbp", "spl": "rsp",
    "r8b": "r8", "r9b": "r9", "r10b": "r10", "r11b": "r11",
    "r12b": "r12", "r13b": "r13", "r14b": "r14", "r15b": "r15",
}


def normalize_register(reg_name: str) -> str:
    """Normalize a register name to its 64-bit equivalent."""
    if not reg_name:
        return reg_name
    reg_lower = reg_name.lower()
    return REG_ALIAS_TO_64.get(reg_lower, reg_lower)


class DisassemblyHelper:
    """Helper for disassembling and analyzing x64 instructions."""

    def __init__(self):
        """Initialize the disassembly helper."""
        if not CAPSTONE_AVAILABLE:
            raise RuntimeError(
                "Capstone is not installed. Install with: pip install capstone"
            )

        # Create Capstone disassembler for x64
        self._cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self._cs.detail = True  # Enable detailed instruction info

        # Build register name map
        self._build_reg_map()

    def _build_reg_map(self):
        """Build a mapping from Capstone register IDs to names."""
        global REG_NAME_MAP
        if REG_NAME_MAP:
            return
        # Use Capstone's reg_name method
        # Common x64 registers
        for i in range(300):  # Capstone register IDs
            try:
                name = self._cs.reg_name(i)
                if name:
                    REG_NAME_MAP[i] = name
            except:
                pass

    def _reg_name(self, reg_id: int) -> Optional[str]:
        """Get register name from Capstone register ID."""
        if reg_id == 0:
            return None
        return self._cs.reg_name(reg_id)

    def _parse_mem_operand(self, mem) -> MemoryOperand:
        """Parse a Capstone memory operand."""
        return MemoryOperand(
            base_reg=self._reg_name(mem.base) if mem.base else None,
            index_reg=self._reg_name(mem.index) if mem.index else None,
            scale=mem.scale,
            disp=mem.disp,
            segment=self._reg_name(mem.segment) if mem.segment else None,
        )

    def disassemble_one(self, code: bytes, address: int) -> Optional[DisassembledInstruction]:
        """Disassemble a single instruction and analyze it.

        Args:
            code: Raw instruction bytes
            address: Virtual address of the instruction

        Returns:
            DisassembledInstruction with analysis info, or None if disassembly fails
        """
        if not CAPSTONE_AVAILABLE:
            return None

        try:
            # Disassemble one instruction
            instructions = list(self._cs.disasm(code, address, count=1))
            if not instructions:
                return None

            insn = instructions[0]

            # Analyze the instruction
            return self._analyze_instruction(insn)
        except Exception as e:
            return None

    def disassemble_many(self, code: bytes, address: int, count: int = 10) -> List[DisassembledInstruction]:
        """Disassemble multiple instructions.

        Args:
            code: Raw instruction bytes
            address: Virtual address of the first instruction
            count: Maximum number of instructions to disassemble

        Returns:
            List of DisassembledInstruction objects
        """
        if not CAPSTONE_AVAILABLE:
            return []

        try:
            result = []
            for insn in self._cs.disasm(code, address, count=count):
                analyzed = self._analyze_instruction(insn)
                if analyzed:
                    result.append(analyzed)
            return result
        except Exception as e:
            return []

    def _analyze_instruction(self, insn) -> DisassembledInstruction:
        """Analyze a Capstone instruction and categorize it.

        Args:
            insn: Capstone instruction object

        Returns:
            DisassembledInstruction with category and operand info
        """
        mnemonic = insn.mnemonic.lower()

        # Start with basic info
        result = DisassembledInstruction(
            address=insn.address,
            size=insn.size,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            bytes_hex=insn.bytes.hex(),
            category=InstructionCategory.UNKNOWN,
        )

        # Get operands if available
        if not insn.operands:
            return self._categorize_no_operands(result, mnemonic)

        operands = insn.operands

        # Categorize based on mnemonic and operands
        if mnemonic in ("mov", "movabs"):
            result = self._categorize_mov(result, operands)
        elif mnemonic in ("movzx", "movsx", "movsxd"):
            result = self._categorize_movzx_movsx(result, operands)
        elif mnemonic == "lea":
            result = self._categorize_lea(result, operands)
        elif mnemonic == "push":
            result = self._categorize_push(result, operands)
        elif mnemonic == "pop":
            result = self._categorize_pop(result, operands)
        elif mnemonic == "call":
            result.category = InstructionCategory.CALL
        elif mnemonic in ("ret", "retn"):
            result.category = InstructionCategory.RET
        elif mnemonic.startswith("cmov"):
            result = self._categorize_cmov(result, operands)
        elif mnemonic in ("add", "sub", "xor", "or", "and", "adc", "sbb", "inc", "dec", "neg", "not"):
            result = self._categorize_arithmetic(result, operands)
        elif mnemonic in ("imul", "mul", "idiv", "div"):
            result = self._categorize_mul_div(result, operands)
        elif mnemonic in ("shl", "shr", "sar", "sal", "rol", "ror", "rcl", "rcr"):
            result = self._categorize_shift(result, operands)
        elif mnemonic in ("cmp", "test"):
            result.category = InstructionCategory.CMP_TEST
        elif mnemonic == "xchg":
            result = self._categorize_xchg(result, operands)
        elif mnemonic.startswith(("movs", "stos", "lods", "cmps", "scas")):
            result.category = InstructionCategory.STRING_OP

        return result

    def _categorize_no_operands(self, result: DisassembledInstruction,
                                 mnemonic: str) -> DisassembledInstruction:
        """Categorize instructions without operands."""
        if mnemonic in ("ret", "retn"):
            result.category = InstructionCategory.RET
        return result

    def _categorize_mov(self, result: DisassembledInstruction,
                        operands) -> DisassembledInstruction:
        """Categorize MOV instruction."""
        if len(operands) < 2:
            return result

        dest = operands[0]
        src = operands[1]

        # Determine destination
        if dest.type == X86_OP_REG:
            result.dest_reg = normalize_register(self._reg_name(dest.reg))

            # Determine source
            if src.type == X86_OP_REG:
                result.category = InstructionCategory.MOV_REG_REG
                result.source_reg = normalize_register(self._reg_name(src.reg))
            elif src.type == X86_OP_MEM:
                result.category = InstructionCategory.MOV_REG_MEM
                result.source_mem = self._parse_mem_operand(src.mem)
            elif src.type == X86_OP_IMM:
                result.category = InstructionCategory.MOV_REG_IMM
                result.immediate = src.imm

        elif dest.type == X86_OP_MEM:
            result.dest_mem = self._parse_mem_operand(dest.mem)

            if src.type == X86_OP_REG:
                result.category = InstructionCategory.MOV_MEM_REG
                result.source_reg = normalize_register(self._reg_name(src.reg))
            elif src.type == X86_OP_IMM:
                result.category = InstructionCategory.MOV_MEM_IMM
                result.immediate = src.imm

        return result

    def _categorize_movzx_movsx(self, result: DisassembledInstruction,
                                 operands) -> DisassembledInstruction:
        """Categorize MOVZX/MOVSX instructions."""
        if len(operands) < 2:
            return result

        dest = operands[0]
        src = operands[1]

        result.category = InstructionCategory.MOVZX_MOVSX

        if dest.type == X86_OP_REG:
            result.dest_reg = normalize_register(self._reg_name(dest.reg))

        if src.type == X86_OP_REG:
            result.source_reg = normalize_register(self._reg_name(src.reg))
        elif src.type == X86_OP_MEM:
            result.source_mem = self._parse_mem_operand(src.mem)

        return result

    def _categorize_lea(self, result: DisassembledInstruction,
                        operands) -> DisassembledInstruction:
        """Categorize LEA instruction."""
        if len(operands) < 2:
            return result

        result.category = InstructionCategory.LEA

        dest = operands[0]
        src = operands[1]

        if dest.type == X86_OP_REG:
            result.dest_reg = normalize_register(self._reg_name(dest.reg))

        if src.type == X86_OP_MEM:
            result.source_mem = self._parse_mem_operand(src.mem)

        return result

    def _categorize_push(self, result: DisassembledInstruction,
                         operands) -> DisassembledInstruction:
        """Categorize PUSH instruction."""
        result.category = InstructionCategory.PUSH

        if operands and operands[0].type == X86_OP_REG:
            result.source_reg = normalize_register(self._reg_name(operands[0].reg))
        elif operands and operands[0].type == X86_OP_IMM:
            result.immediate = operands[0].imm
        elif operands and operands[0].type == X86_OP_MEM:
            result.source_mem = self._parse_mem_operand(operands[0].mem)

        return result

    def _categorize_pop(self, result: DisassembledInstruction,
                        operands) -> DisassembledInstruction:
        """Categorize POP instruction."""
        result.category = InstructionCategory.POP

        if operands and operands[0].type == X86_OP_REG:
            result.dest_reg = normalize_register(self._reg_name(operands[0].reg))
        elif operands and operands[0].type == X86_OP_MEM:
            result.dest_mem = self._parse_mem_operand(operands[0].mem)

        return result

    def _categorize_cmov(self, result: DisassembledInstruction,
                         operands) -> DisassembledInstruction:
        """Categorize CMOVcc instruction."""
        if len(operands) < 2:
            return result

        result.category = InstructionCategory.CMOV

        dest = operands[0]
        src = operands[1]

        if dest.type == X86_OP_REG:
            result.dest_reg = normalize_register(self._reg_name(dest.reg))

        if src.type == X86_OP_REG:
            result.source_reg = normalize_register(self._reg_name(src.reg))
        elif src.type == X86_OP_MEM:
            result.source_mem = self._parse_mem_operand(src.mem)

        return result

    def _categorize_arithmetic(self, result: DisassembledInstruction,
                               operands) -> DisassembledInstruction:
        """Categorize arithmetic instructions (add, sub, xor, etc.)."""
        result.category = InstructionCategory.ARITHMETIC

        if operands:
            dest = operands[0]
            if dest.type == X86_OP_REG:
                result.dest_reg = normalize_register(self._reg_name(dest.reg))
            elif dest.type == X86_OP_MEM:
                result.dest_mem = self._parse_mem_operand(dest.mem)

            if len(operands) > 1:
                src = operands[1]
                if src.type == X86_OP_REG:
                    result.source_reg = normalize_register(self._reg_name(src.reg))
                elif src.type == X86_OP_MEM:
                    result.source_mem = self._parse_mem_operand(src.mem)
                elif src.type == X86_OP_IMM:
                    result.immediate = src.imm

        return result

    def _categorize_mul_div(self, result: DisassembledInstruction,
                            operands) -> DisassembledInstruction:
        """Categorize multiply/divide instructions."""
        result.category = InstructionCategory.MUL_DIV

        if operands:
            op = operands[0]
            if op.type == X86_OP_REG:
                result.source_reg = normalize_register(self._reg_name(op.reg))
            elif op.type == X86_OP_MEM:
                result.source_mem = self._parse_mem_operand(op.mem)

        # MUL/DIV implicitly use RAX/RDX
        result.dest_reg = "rax"  # Result goes to RAX (and RDX for 128-bit)

        return result

    def _categorize_shift(self, result: DisassembledInstruction,
                          operands) -> DisassembledInstruction:
        """Categorize shift/rotate instructions."""
        result.category = InstructionCategory.SHIFT

        if operands:
            dest = operands[0]
            if dest.type == X86_OP_REG:
                result.dest_reg = normalize_register(self._reg_name(dest.reg))
            elif dest.type == X86_OP_MEM:
                result.dest_mem = self._parse_mem_operand(dest.mem)

            if len(operands) > 1:
                src = operands[1]
                if src.type == X86_OP_IMM:
                    result.immediate = src.imm
                elif src.type == X86_OP_REG:
                    result.source_reg = normalize_register(self._reg_name(src.reg))

        return result

    def _categorize_xchg(self, result: DisassembledInstruction,
                         operands) -> DisassembledInstruction:
        """Categorize XCHG instruction."""
        result.category = InstructionCategory.XCHG

        if len(operands) >= 2:
            if operands[0].type == X86_OP_REG:
                result.dest_reg = normalize_register(self._reg_name(operands[0].reg))
            if operands[1].type == X86_OP_REG:
                result.source_reg = normalize_register(self._reg_name(operands[1].reg))

        return result

    def get_modified_register(self, insn: DisassembledInstruction) -> Optional[str]:
        """Get the register modified by an instruction.

        Args:
            insn: Analyzed instruction

        Returns:
            Name of the modified register (64-bit normalized), or None
        """
        return insn.dest_reg

    def get_source_info(self, insn: DisassembledInstruction) -> Tuple[str, str]:
        """Get the data source information from an instruction.

        Args:
            insn: Analyzed instruction

        Returns:
            Tuple of (source_type, source_detail) where source_type is one of:
            - "register": Source is another register
            - "memory": Source is memory location
            - "immediate": Source is a constant value
            - "computed": Value is computed (arithmetic, etc.)
            - "function_return": Value comes from function call
            - "unknown": Cannot determine source
        """
        cat = insn.category

        if cat == InstructionCategory.MOV_REG_REG:
            return ("register", insn.source_reg or "unknown")

        elif cat == InstructionCategory.MOV_REG_MEM:
            return ("memory", str(insn.source_mem) if insn.source_mem else "unknown")

        elif cat == InstructionCategory.MOV_REG_IMM:
            return ("immediate", f"0x{insn.immediate:x}" if insn.immediate is not None else "unknown")

        elif cat == InstructionCategory.MOVZX_MOVSX:
            if insn.source_reg:
                return ("register", insn.source_reg)
            elif insn.source_mem:
                return ("memory", str(insn.source_mem))
            return ("unknown", "")

        elif cat == InstructionCategory.LEA:
            # LEA computes an address, the base register is the primary source
            if insn.source_mem and insn.source_mem.base_reg:
                return ("address_computation", insn.source_mem.base_reg)
            return ("address_computation", str(insn.source_mem) if insn.source_mem else "unknown")

        elif cat == InstructionCategory.POP:
            return ("stack_pop", "[rsp]")

        elif cat == InstructionCategory.CALL:
            return ("function_return", "")

        elif cat in (InstructionCategory.ARITHMETIC, InstructionCategory.SHIFT):
            # Computed value - indicate the operation
            return ("computed", f"{insn.mnemonic} operation")

        elif cat == InstructionCategory.MUL_DIV:
            return ("computed", f"{insn.mnemonic} with implicit rax/rdx")

        elif cat == InstructionCategory.CMOV:
            # Conditional - may or may not have been taken
            if insn.source_reg:
                return ("conditional_register", insn.source_reg)
            elif insn.source_mem:
                return ("conditional_memory", str(insn.source_mem))
            return ("conditional", "unknown")

        elif cat == InstructionCategory.XCHG:
            return ("exchange", insn.source_reg or "unknown")

        return ("unknown", "")

    def get_input_operands(self, insn: DisassembledInstruction) -> List[dict]:
        """Get all input operands that contribute to the result for taint analysis.

        For computed operations (xor, add, sub, etc.), returns ALL input operands
        that contribute to the final value, enabling full taint tracking.

        Args:
            insn: Analyzed instruction

        Returns:
            List of input operand dicts with:
            - type: "register", "memory", "immediate"
            - value: register name, memory operand string, or immediate value
            - is_dest_also_source: True if dest reg is also a source (e.g., xor r8, rax)
        """
        cat = insn.category
        inputs = []

        if cat == InstructionCategory.MOV_REG_REG:
            # Only source register contributes
            if insn.source_reg:
                inputs.append({"type": "register", "value": insn.source_reg, "is_dest_also_source": False})

        elif cat == InstructionCategory.MOV_REG_MEM:
            if insn.source_mem:
                inputs.append({"type": "memory", "value": str(insn.source_mem), "is_dest_also_source": False})

        elif cat == InstructionCategory.MOV_REG_IMM:
            if insn.immediate is not None:
                inputs.append({"type": "immediate", "value": f"0x{insn.immediate:x}", "is_dest_also_source": False})

        elif cat == InstructionCategory.MOVZX_MOVSX:
            if insn.source_reg:
                inputs.append({"type": "register", "value": insn.source_reg, "is_dest_also_source": False})
            elif insn.source_mem:
                inputs.append({"type": "memory", "value": str(insn.source_mem), "is_dest_also_source": False})

        elif cat == InstructionCategory.LEA:
            # LEA computes address - both base and index contribute
            if insn.source_mem:
                if insn.source_mem.base_reg:
                    inputs.append({"type": "register", "value": insn.source_mem.base_reg, "is_dest_also_source": False})
                if insn.source_mem.index_reg:
                    inputs.append({"type": "register", "value": insn.source_mem.index_reg, "is_dest_also_source": False})
                # Displacement is a constant, add as immediate if non-zero
                if insn.source_mem.disp != 0:
                    inputs.append({"type": "immediate", "value": f"0x{insn.source_mem.disp:x}", "is_dest_also_source": False})

        elif cat == InstructionCategory.POP:
            # Value comes from stack
            inputs.append({"type": "memory", "value": "[rsp]", "is_dest_also_source": False})

        elif cat == InstructionCategory.CALL:
            # Return value - no direct input operand
            inputs.append({"type": "function_return", "value": "", "is_dest_also_source": False})

        elif cat == InstructionCategory.ARITHMETIC:
            # IMPORTANT: For arithmetic operations, BOTH operands contribute
            # e.g., xor r8, rax -> result depends on both r8 (old value) and rax
            # e.g., add rax, rbx -> result depends on both rax (old value) and rbx

            # Check if dest register is also a source (most arithmetic is like this)
            if insn.dest_reg:
                # Dest reg's old value contributes to result
                inputs.append({"type": "register", "value": insn.dest_reg, "is_dest_also_source": True})

            # Add the second operand
            if insn.source_reg:
                inputs.append({"type": "register", "value": insn.source_reg, "is_dest_also_source": False})
            elif insn.source_mem:
                inputs.append({"type": "memory", "value": str(insn.source_mem), "is_dest_also_source": False})
            elif insn.immediate is not None:
                inputs.append({"type": "immediate", "value": f"0x{insn.immediate:x}", "is_dest_also_source": False})

            # Special case: single operand instructions like inc, dec, neg, not
            if insn.mnemonic.lower() in ("inc", "dec", "neg", "not"):
                # Only the dest/source operand contributes (already added above)
                pass

        elif cat == InstructionCategory.SHIFT:
            # Shift operations: value being shifted + shift count
            if insn.dest_reg:
                # The value being shifted
                inputs.append({"type": "register", "value": insn.dest_reg, "is_dest_also_source": True})

            # Shift count
            if insn.immediate is not None:
                inputs.append({"type": "immediate", "value": f"{insn.immediate}", "is_dest_also_source": False})
            elif insn.source_reg:
                # Variable shift (e.g., shl rax, cl)
                inputs.append({"type": "register", "value": insn.source_reg, "is_dest_also_source": False})

        elif cat == InstructionCategory.MUL_DIV:
            # MUL/DIV use implicit RAX/RDX
            inputs.append({"type": "register", "value": "rax", "is_dest_also_source": True})
            if insn.mnemonic.lower() in ("div", "idiv"):
                inputs.append({"type": "register", "value": "rdx", "is_dest_also_source": True})
            # The explicit operand
            if insn.source_reg:
                inputs.append({"type": "register", "value": insn.source_reg, "is_dest_also_source": False})
            elif insn.source_mem:
                inputs.append({"type": "memory", "value": str(insn.source_mem), "is_dest_also_source": False})

        elif cat == InstructionCategory.CMOV:
            # Conditional move - both old dest value and source contribute (conditionally)
            if insn.dest_reg:
                inputs.append({"type": "register", "value": insn.dest_reg, "is_dest_also_source": True})
            if insn.source_reg:
                inputs.append({"type": "register", "value": insn.source_reg, "is_dest_also_source": False})
            elif insn.source_mem:
                inputs.append({"type": "memory", "value": str(insn.source_mem), "is_dest_also_source": False})

        elif cat == InstructionCategory.XCHG:
            # Both registers contribute to each other
            if insn.dest_reg:
                inputs.append({"type": "register", "value": insn.dest_reg, "is_dest_also_source": True})
            if insn.source_reg:
                inputs.append({"type": "register", "value": insn.source_reg, "is_dest_also_source": False})

        return inputs


def is_capstone_available() -> bool:
    """Check if Capstone is available."""
    return CAPSTONE_AVAILABLE


def get_disassembly_helper() -> Optional[DisassemblyHelper]:
    """Get a DisassemblyHelper instance if Capstone is available.

    Returns:
        DisassemblyHelper instance, or None if Capstone is not installed
    """
    if not CAPSTONE_AVAILABLE:
        return None
    try:
        return DisassemblyHelper()
    except Exception:
        return None
