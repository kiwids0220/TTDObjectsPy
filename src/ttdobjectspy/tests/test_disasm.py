"""Unit tests for the disassembly helper module.

These tests verify the Capstone-based disassembly and instruction categorization.
"""

import unittest


class TestCapstoneAvailability(unittest.TestCase):
    """Test Capstone availability detection."""

    def test_is_capstone_available(self):
        """Test the is_capstone_available function."""
        from ttdobjectspy.disasm import is_capstone_available

        # Should return True if capstone is installed, False otherwise
        result = is_capstone_available()
        self.assertIsInstance(result, bool)

    def test_get_disassembly_helper(self):
        """Test getting a disassembly helper."""
        from ttdobjectspy.disasm import get_disassembly_helper, is_capstone_available

        helper = get_disassembly_helper()

        if is_capstone_available():
            self.assertIsNotNone(helper)
        else:
            self.assertIsNone(helper)


class TestRegisterNormalization(unittest.TestCase):
    """Test register name normalization."""

    def test_normalize_64bit_registers(self):
        """Test that 64-bit register names pass through unchanged."""
        from ttdobjectspy.disasm import normalize_register

        self.assertEqual(normalize_register("rax"), "rax")
        self.assertEqual(normalize_register("rbx"), "rbx")
        self.assertEqual(normalize_register("rcx"), "rcx")
        self.assertEqual(normalize_register("r8"), "r8")
        self.assertEqual(normalize_register("r15"), "r15")
        self.assertEqual(normalize_register("rip"), "rip")

    def test_normalize_32bit_registers(self):
        """Test that 32-bit register names are normalized to 64-bit."""
        from ttdobjectspy.disasm import normalize_register

        self.assertEqual(normalize_register("eax"), "rax")
        self.assertEqual(normalize_register("ebx"), "rbx")
        self.assertEqual(normalize_register("ecx"), "rcx")
        self.assertEqual(normalize_register("edx"), "rdx")
        self.assertEqual(normalize_register("esi"), "rsi")
        self.assertEqual(normalize_register("edi"), "rdi")
        self.assertEqual(normalize_register("r8d"), "r8")
        self.assertEqual(normalize_register("r15d"), "r15")

    def test_normalize_16bit_registers(self):
        """Test that 16-bit register names are normalized to 64-bit."""
        from ttdobjectspy.disasm import normalize_register

        self.assertEqual(normalize_register("ax"), "rax")
        self.assertEqual(normalize_register("bx"), "rbx")
        self.assertEqual(normalize_register("cx"), "rcx")
        self.assertEqual(normalize_register("r8w"), "r8")

    def test_normalize_8bit_registers(self):
        """Test that 8-bit register names are normalized to 64-bit."""
        from ttdobjectspy.disasm import normalize_register

        self.assertEqual(normalize_register("al"), "rax")
        self.assertEqual(normalize_register("ah"), "rax")
        self.assertEqual(normalize_register("bl"), "rbx")
        self.assertEqual(normalize_register("cl"), "rcx")
        self.assertEqual(normalize_register("r8b"), "r8")

    def test_normalize_case_insensitive(self):
        """Test that normalization is case-insensitive."""
        from ttdobjectspy.disasm import normalize_register

        self.assertEqual(normalize_register("RAX"), "rax")
        self.assertEqual(normalize_register("EAX"), "rax")
        self.assertEqual(normalize_register("Rax"), "rax")


@unittest.skipUnless(
    __import__('ttdobjectspy.disasm', fromlist=['is_capstone_available']).is_capstone_available(),
    "Capstone not available"
)
class TestDisassemblyHelper(unittest.TestCase):
    """Test the DisassemblyHelper class."""

    def setUp(self):
        """Set up test fixtures."""
        from ttdobjectspy.disasm import DisassemblyHelper
        self.helper = DisassemblyHelper()

    def test_disassemble_mov_reg_imm(self):
        """Test disassembling MOV reg, imm."""
        # mov rax, 0x1234567890abcdef (48 b8 ef cd ab 90 78 56 34 12)
        code = bytes.fromhex("48b8efcdab9078563412")
        insn = self.helper.disassemble_one(code, 0x1000)

        self.assertIsNotNone(insn)
        self.assertEqual(insn.mnemonic.lower(), "movabs")
        from ttdobjectspy.disasm import InstructionCategory
        self.assertEqual(insn.category, InstructionCategory.MOV_REG_IMM)
        self.assertEqual(insn.dest_reg, "rax")
        self.assertEqual(insn.immediate, 0x1234567890abcdef)

    def test_disassemble_mov_reg_reg(self):
        """Test disassembling MOV reg, reg."""
        # mov rax, rbx (48 89 d8)
        code = bytes.fromhex("4889d8")
        insn = self.helper.disassemble_one(code, 0x1000)

        self.assertIsNotNone(insn)
        self.assertEqual(insn.mnemonic.lower(), "mov")
        from ttdobjectspy.disasm import InstructionCategory
        self.assertEqual(insn.category, InstructionCategory.MOV_REG_REG)
        self.assertEqual(insn.dest_reg, "rax")
        self.assertEqual(insn.source_reg, "rbx")

    def test_disassemble_mov_reg_mem(self):
        """Test disassembling MOV reg, [mem]."""
        # mov rax, [rbx] (48 8b 03)
        code = bytes.fromhex("488b03")
        insn = self.helper.disassemble_one(code, 0x1000)

        self.assertIsNotNone(insn)
        self.assertEqual(insn.mnemonic.lower(), "mov")
        from ttdobjectspy.disasm import InstructionCategory
        self.assertEqual(insn.category, InstructionCategory.MOV_REG_MEM)
        self.assertEqual(insn.dest_reg, "rax")
        self.assertIsNotNone(insn.source_mem)
        self.assertEqual(insn.source_mem.base_reg, "rbx")

    def test_disassemble_lea(self):
        """Test disassembling LEA instruction."""
        # lea rax, [rbx+rcx*4+0x10] (48 8d 44 8b 10)
        code = bytes.fromhex("488d448b10")
        insn = self.helper.disassemble_one(code, 0x1000)

        self.assertIsNotNone(insn)
        self.assertEqual(insn.mnemonic.lower(), "lea")
        from ttdobjectspy.disasm import InstructionCategory
        self.assertEqual(insn.category, InstructionCategory.LEA)
        self.assertEqual(insn.dest_reg, "rax")
        self.assertIsNotNone(insn.source_mem)
        self.assertEqual(insn.source_mem.base_reg, "rbx")
        self.assertEqual(insn.source_mem.index_reg, "rcx")
        self.assertEqual(insn.source_mem.scale, 4)
        self.assertEqual(insn.source_mem.disp, 0x10)

    def test_disassemble_push(self):
        """Test disassembling PUSH instruction."""
        # push rax (50)
        code = bytes.fromhex("50")
        insn = self.helper.disassemble_one(code, 0x1000)

        self.assertIsNotNone(insn)
        self.assertEqual(insn.mnemonic.lower(), "push")
        from ttdobjectspy.disasm import InstructionCategory
        self.assertEqual(insn.category, InstructionCategory.PUSH)
        self.assertEqual(insn.source_reg, "rax")

    def test_disassemble_pop(self):
        """Test disassembling POP instruction."""
        # pop rbx (5b)
        code = bytes.fromhex("5b")
        insn = self.helper.disassemble_one(code, 0x1000)

        self.assertIsNotNone(insn)
        self.assertEqual(insn.mnemonic.lower(), "pop")
        from ttdobjectspy.disasm import InstructionCategory
        self.assertEqual(insn.category, InstructionCategory.POP)
        self.assertEqual(insn.dest_reg, "rbx")

    def test_disassemble_add(self):
        """Test disassembling ADD instruction."""
        # add rax, rbx (48 01 d8)
        code = bytes.fromhex("4801d8")
        insn = self.helper.disassemble_one(code, 0x1000)

        self.assertIsNotNone(insn)
        self.assertEqual(insn.mnemonic.lower(), "add")
        from ttdobjectspy.disasm import InstructionCategory
        self.assertEqual(insn.category, InstructionCategory.ARITHMETIC)
        self.assertEqual(insn.dest_reg, "rax")
        self.assertEqual(insn.source_reg, "rbx")

    def test_disassemble_xor(self):
        """Test disassembling XOR instruction."""
        # xor eax, eax (31 c0)
        code = bytes.fromhex("31c0")
        insn = self.helper.disassemble_one(code, 0x1000)

        self.assertIsNotNone(insn)
        self.assertEqual(insn.mnemonic.lower(), "xor")
        from ttdobjectspy.disasm import InstructionCategory
        self.assertEqual(insn.category, InstructionCategory.ARITHMETIC)
        # 32-bit registers should be normalized to 64-bit
        self.assertEqual(insn.dest_reg, "rax")

    def test_disassemble_call(self):
        """Test disassembling CALL instruction."""
        # call [rip+0x1234] (ff 15 34 12 00 00)
        code = bytes.fromhex("ff1534120000")
        insn = self.helper.disassemble_one(code, 0x1000)

        self.assertIsNotNone(insn)
        self.assertEqual(insn.mnemonic.lower(), "call")
        from ttdobjectspy.disasm import InstructionCategory
        self.assertEqual(insn.category, InstructionCategory.CALL)

    def test_disassemble_ret(self):
        """Test disassembling RET instruction."""
        # ret (c3)
        code = bytes.fromhex("c3")
        insn = self.helper.disassemble_one(code, 0x1000)

        self.assertIsNotNone(insn)
        self.assertEqual(insn.mnemonic.lower(), "ret")
        from ttdobjectspy.disasm import InstructionCategory
        self.assertEqual(insn.category, InstructionCategory.RET)

    def test_get_source_info_immediate(self):
        """Test get_source_info for immediate source."""
        # mov rax, 0x42
        code = bytes.fromhex("48c7c042000000")
        insn = self.helper.disassemble_one(code, 0x1000)

        source_type, source_detail = self.helper.get_source_info(insn)
        self.assertEqual(source_type, "immediate")
        self.assertIn("42", source_detail.lower())

    def test_get_source_info_register(self):
        """Test get_source_info for register source."""
        # mov rax, rbx
        code = bytes.fromhex("4889d8")
        insn = self.helper.disassemble_one(code, 0x1000)

        source_type, source_detail = self.helper.get_source_info(insn)
        self.assertEqual(source_type, "register")
        self.assertEqual(source_detail, "rbx")

    def test_get_source_info_memory(self):
        """Test get_source_info for memory source."""
        # mov rax, [rbx]
        code = bytes.fromhex("488b03")
        insn = self.helper.disassemble_one(code, 0x1000)

        source_type, source_detail = self.helper.get_source_info(insn)
        self.assertEqual(source_type, "memory")
        self.assertIn("rbx", source_detail.lower())

    def test_get_source_info_lea(self):
        """Test get_source_info for LEA instruction."""
        # lea rax, [rbx]
        code = bytes.fromhex("488d03")
        insn = self.helper.disassemble_one(code, 0x1000)

        source_type, source_detail = self.helper.get_source_info(insn)
        self.assertEqual(source_type, "address_computation")
        self.assertEqual(source_detail, "rbx")

    def test_get_modified_register(self):
        """Test get_modified_register."""
        # mov rax, rbx
        code = bytes.fromhex("4889d8")
        insn = self.helper.disassemble_one(code, 0x1000)

        modified = self.helper.get_modified_register(insn)
        self.assertEqual(modified, "rax")

    def test_disassemble_many(self):
        """Test disassembling multiple instructions."""
        # mov rax, rbx; add rax, rcx; ret
        code = bytes.fromhex("4889d84801c8c3")
        instructions = self.helper.disassemble_many(code, 0x1000, count=3)

        self.assertEqual(len(instructions), 3)
        self.assertEqual(instructions[0].mnemonic.lower(), "mov")
        self.assertEqual(instructions[1].mnemonic.lower(), "add")
        self.assertEqual(instructions[2].mnemonic.lower(), "ret")

    def test_disassemble_invalid_bytes(self):
        """Test disassembling invalid instruction bytes."""
        # Invalid bytes that don't form a valid instruction
        code = bytes.fromhex("0f0b")  # UD2 (undefined instruction)
        insn = self.helper.disassemble_one(code, 0x1000)

        # Should still disassemble (UD2 is a valid instruction)
        self.assertIsNotNone(insn)

    def test_disassemble_empty_bytes(self):
        """Test disassembling empty bytes."""
        code = b""
        insn = self.helper.disassemble_one(code, 0x1000)
        self.assertIsNone(insn)


class TestInstructionCategory(unittest.TestCase):
    """Test the InstructionCategory enum."""

    def test_instruction_categories_exist(self):
        """Test that all expected instruction categories exist."""
        from ttdobjectspy.disasm import InstructionCategory

        expected_categories = [
            "MOV_REG_REG", "MOV_REG_MEM", "MOV_REG_IMM",
            "MOV_MEM_REG", "MOV_MEM_IMM",
            "LEA", "PUSH", "POP", "CALL", "RET",
            "ARITHMETIC", "MUL_DIV", "SHIFT",
            "CMP_TEST", "XCHG", "CMOV",
            "MOVZX_MOVSX", "STRING_OP", "UNKNOWN"
        ]

        for cat_name in expected_categories:
            self.assertTrue(
                hasattr(InstructionCategory, cat_name),
                f"Missing category: {cat_name}"
            )


class TestMemoryOperand(unittest.TestCase):
    """Test the MemoryOperand dataclass."""

    def test_memory_operand_str(self):
        """Test MemoryOperand string representation."""
        from ttdobjectspy.disasm import MemoryOperand

        # Simple base register
        op = MemoryOperand(base_reg="rax")
        self.assertIn("rax", str(op))

        # Base + displacement
        op = MemoryOperand(base_reg="rbx", disp=0x10)
        result = str(op)
        self.assertIn("rbx", result)
        self.assertIn("10", result.lower())

        # Base + index*scale + displacement
        op = MemoryOperand(base_reg="rbx", index_reg="rcx", scale=4, disp=0x20)
        result = str(op)
        self.assertIn("rbx", result)
        self.assertIn("rcx", result)
        self.assertIn("4", result)


class TestDataFlowStep(unittest.TestCase):
    """Test the DataFlowStep dataclass from cursor.py."""

    def test_data_flow_step_to_dict(self):
        """Test DataFlowStep.to_dict() serialization."""
        from ttdobjectspy.cursor import DataFlowStep
        from ttdobjectspy.ttd_types import Position

        step = DataFlowStep(
            position=Position(0x100, 0x50),
            instruction_address=0x7ff6abcd1234,
            instruction_text="mov rax, rbx",
            tracking_type="register",
            tracking_target="rax",
            value_at_step=0x12345678,
            source_type="register",
            source_detail="rbx",
            registers={"rax": 0x12345678, "rbx": 0x87654321}
        )

        d = step.to_dict()

        self.assertEqual(d["instruction_address"], "0x7ff6abcd1234")
        self.assertEqual(d["instruction_text"], "mov rax, rbx")
        self.assertEqual(d["tracking_type"], "register")
        self.assertEqual(d["tracking_target"], "rax")
        self.assertEqual(d["value_at_step"], "0x12345678")
        self.assertEqual(d["source_type"], "register")
        self.assertEqual(d["source_detail"], "rbx")
        self.assertIn("rax", d["registers"])


class TestDataFlowTraceResult(unittest.TestCase):
    """Test the DataFlowTraceResult dataclass from cursor.py."""

    def test_data_flow_trace_result_to_dict(self):
        """Test DataFlowTraceResult.to_dict() serialization."""
        from ttdobjectspy.cursor import DataFlowTraceResult

        result = DataFlowTraceResult(
            success=True,
            steps=[],
            origin_found=True,
            origin_type="constant",
            origin_detail="0x42",
            termination_reason="origin_found"
        )

        d = result.to_dict()

        self.assertTrue(d["success"])
        self.assertEqual(d["step_count"], 0)
        self.assertTrue(d["origin_found"])
        self.assertEqual(d["origin_type"], "constant")
        self.assertEqual(d["origin_detail"], "0x42")
        self.assertEqual(d["termination_reason"], "origin_found")

    def test_data_flow_trace_result_with_steps(self):
        """Test DataFlowTraceResult with steps."""
        from ttdobjectspy.cursor import DataFlowStep, DataFlowTraceResult
        from ttdobjectspy.ttd_types import Position

        step = DataFlowStep(
            position=Position(0x100, 0x50),
            instruction_address=0x1000,
            instruction_text="mov rax, 0x42",
            tracking_type="register",
            tracking_target="rax",
            value_at_step=0x42,
            source_type="immediate",
            source_detail="0x42",
            registers=None
        )

        result = DataFlowTraceResult(
            success=True,
            steps=[step],
            origin_found=True,
            origin_type="constant",
            origin_detail="0x42",
            termination_reason="origin_found"
        )

        d = result.to_dict()

        self.assertEqual(d["step_count"], 1)
        self.assertEqual(len(d["steps"]), 1)
        self.assertEqual(d["steps"][0]["instruction_address"], "0x1000")


if __name__ == "__main__":
    unittest.main()
