// SPDX-License-Identifier: Open BSV License Version 5
// All 256 Bitcoin opcodes as static constants.
// Reference: https://wiki.bitcoinsv.io/index.php/Opcodes_used_in_Bitcoin_Script

import Foundation

/// All Bitcoin script opcodes.
public struct OpCodes {
    private init() {}

    // MARK: - Push Value (0x00)

    public static let OP_0: UInt8 = 0x00
    public static let OP_FALSE: UInt8 = 0x00

    // MARK: - Data Push (0x01 - 0x4b): push next N bytes

    public static let OP_DATA_1: UInt8 = 0x01
    public static let OP_DATA_2: UInt8 = 0x02
    public static let OP_DATA_3: UInt8 = 0x03
    public static let OP_DATA_4: UInt8 = 0x04
    public static let OP_DATA_5: UInt8 = 0x05
    public static let OP_DATA_6: UInt8 = 0x06
    public static let OP_DATA_7: UInt8 = 0x07
    public static let OP_DATA_8: UInt8 = 0x08
    public static let OP_DATA_9: UInt8 = 0x09
    public static let OP_DATA_10: UInt8 = 0x0a
    public static let OP_DATA_11: UInt8 = 0x0b
    public static let OP_DATA_12: UInt8 = 0x0c
    public static let OP_DATA_13: UInt8 = 0x0d
    public static let OP_DATA_14: UInt8 = 0x0e
    public static let OP_DATA_15: UInt8 = 0x0f
    public static let OP_DATA_16: UInt8 = 0x10
    public static let OP_DATA_17: UInt8 = 0x11
    public static let OP_DATA_18: UInt8 = 0x12
    public static let OP_DATA_19: UInt8 = 0x13
    public static let OP_DATA_20: UInt8 = 0x14
    public static let OP_DATA_21: UInt8 = 0x15
    public static let OP_DATA_22: UInt8 = 0x16
    public static let OP_DATA_23: UInt8 = 0x17
    public static let OP_DATA_24: UInt8 = 0x18
    public static let OP_DATA_25: UInt8 = 0x19
    public static let OP_DATA_26: UInt8 = 0x1a
    public static let OP_DATA_27: UInt8 = 0x1b
    public static let OP_DATA_28: UInt8 = 0x1c
    public static let OP_DATA_29: UInt8 = 0x1d
    public static let OP_DATA_30: UInt8 = 0x1e
    public static let OP_DATA_31: UInt8 = 0x1f
    public static let OP_DATA_32: UInt8 = 0x20
    public static let OP_DATA_33: UInt8 = 0x21
    public static let OP_DATA_34: UInt8 = 0x22
    public static let OP_DATA_35: UInt8 = 0x23
    public static let OP_DATA_36: UInt8 = 0x24
    public static let OP_DATA_37: UInt8 = 0x25
    public static let OP_DATA_38: UInt8 = 0x26
    public static let OP_DATA_39: UInt8 = 0x27
    public static let OP_DATA_40: UInt8 = 0x28
    public static let OP_DATA_41: UInt8 = 0x29
    public static let OP_DATA_42: UInt8 = 0x2a
    public static let OP_DATA_43: UInt8 = 0x2b
    public static let OP_DATA_44: UInt8 = 0x2c
    public static let OP_DATA_45: UInt8 = 0x2d
    public static let OP_DATA_46: UInt8 = 0x2e
    public static let OP_DATA_47: UInt8 = 0x2f
    public static let OP_DATA_48: UInt8 = 0x30
    public static let OP_DATA_49: UInt8 = 0x31
    public static let OP_DATA_50: UInt8 = 0x32
    public static let OP_DATA_51: UInt8 = 0x33
    public static let OP_DATA_52: UInt8 = 0x34
    public static let OP_DATA_53: UInt8 = 0x35
    public static let OP_DATA_54: UInt8 = 0x36
    public static let OP_DATA_55: UInt8 = 0x37
    public static let OP_DATA_56: UInt8 = 0x38
    public static let OP_DATA_57: UInt8 = 0x39
    public static let OP_DATA_58: UInt8 = 0x3a
    public static let OP_DATA_59: UInt8 = 0x3b
    public static let OP_DATA_60: UInt8 = 0x3c
    public static let OP_DATA_61: UInt8 = 0x3d
    public static let OP_DATA_62: UInt8 = 0x3e
    public static let OP_DATA_63: UInt8 = 0x3f
    public static let OP_DATA_64: UInt8 = 0x40
    public static let OP_DATA_65: UInt8 = 0x41
    public static let OP_DATA_66: UInt8 = 0x42
    public static let OP_DATA_67: UInt8 = 0x43
    public static let OP_DATA_68: UInt8 = 0x44
    public static let OP_DATA_69: UInt8 = 0x45
    public static let OP_DATA_70: UInt8 = 0x46
    public static let OP_DATA_71: UInt8 = 0x47
    public static let OP_DATA_72: UInt8 = 0x48
    public static let OP_DATA_73: UInt8 = 0x49
    public static let OP_DATA_74: UInt8 = 0x4a
    public static let OP_DATA_75: UInt8 = 0x4b

    // MARK: - Extended Data Push

    public static let OP_PUSHDATA1: UInt8 = 0x4c
    public static let OP_PUSHDATA2: UInt8 = 0x4d
    public static let OP_PUSHDATA4: UInt8 = 0x4e

    // MARK: - Constants

    public static let OP_1NEGATE: UInt8 = 0x4f
    public static let OP_RESERVED: UInt8 = 0x50
    public static let OP_1: UInt8 = 0x51
    public static let OP_TRUE: UInt8 = 0x51
    public static let OP_2: UInt8 = 0x52
    public static let OP_3: UInt8 = 0x53
    public static let OP_4: UInt8 = 0x54
    public static let OP_5: UInt8 = 0x55
    public static let OP_6: UInt8 = 0x56
    public static let OP_7: UInt8 = 0x57
    public static let OP_8: UInt8 = 0x58
    public static let OP_9: UInt8 = 0x59
    public static let OP_10: UInt8 = 0x5a
    public static let OP_11: UInt8 = 0x5b
    public static let OP_12: UInt8 = 0x5c
    public static let OP_13: UInt8 = 0x5d
    public static let OP_14: UInt8 = 0x5e
    public static let OP_15: UInt8 = 0x5f
    public static let OP_16: UInt8 = 0x60

    // MARK: - Flow Control

    public static let OP_NOP: UInt8 = 0x61
    public static let OP_VER: UInt8 = 0x62
    public static let OP_IF: UInt8 = 0x63
    public static let OP_NOTIF: UInt8 = 0x64
    public static let OP_VERIF: UInt8 = 0x65
    public static let OP_VERNOTIF: UInt8 = 0x66
    public static let OP_ELSE: UInt8 = 0x67
    public static let OP_ENDIF: UInt8 = 0x68
    public static let OP_VERIFY: UInt8 = 0x69
    public static let OP_RETURN: UInt8 = 0x6a

    // MARK: - Stack Operations

    public static let OP_TOALTSTACK: UInt8 = 0x6b
    public static let OP_FROMALTSTACK: UInt8 = 0x6c
    public static let OP_2DROP: UInt8 = 0x6d
    public static let OP_2DUP: UInt8 = 0x6e
    public static let OP_3DUP: UInt8 = 0x6f
    public static let OP_2OVER: UInt8 = 0x70
    public static let OP_2ROT: UInt8 = 0x71
    public static let OP_2SWAP: UInt8 = 0x72
    public static let OP_IFDUP: UInt8 = 0x73
    public static let OP_DEPTH: UInt8 = 0x74
    public static let OP_DROP: UInt8 = 0x75
    public static let OP_DUP: UInt8 = 0x76
    public static let OP_NIP: UInt8 = 0x77
    public static let OP_OVER: UInt8 = 0x78
    public static let OP_PICK: UInt8 = 0x79
    public static let OP_ROLL: UInt8 = 0x7a
    public static let OP_ROT: UInt8 = 0x7b
    public static let OP_SWAP: UInt8 = 0x7c
    public static let OP_TUCK: UInt8 = 0x7d

    // MARK: - Splice Operations

    public static let OP_CAT: UInt8 = 0x7e
    public static let OP_SPLIT: UInt8 = 0x7f
    public static let OP_NUM2BIN: UInt8 = 0x80
    public static let OP_BIN2NUM: UInt8 = 0x81
    public static let OP_SIZE: UInt8 = 0x82

    // MARK: - Bitwise Logic

    public static let OP_INVERT: UInt8 = 0x83
    public static let OP_AND: UInt8 = 0x84
    public static let OP_OR: UInt8 = 0x85
    public static let OP_XOR: UInt8 = 0x86
    public static let OP_EQUAL: UInt8 = 0x87
    public static let OP_EQUALVERIFY: UInt8 = 0x88
    public static let OP_RESERVED1: UInt8 = 0x89
    public static let OP_RESERVED2: UInt8 = 0x8a

    // MARK: - Arithmetic

    public static let OP_1ADD: UInt8 = 0x8b
    public static let OP_1SUB: UInt8 = 0x8c
    public static let OP_2MUL: UInt8 = 0x8d
    public static let OP_2DIV: UInt8 = 0x8e
    public static let OP_NEGATE: UInt8 = 0x8f
    public static let OP_ABS: UInt8 = 0x90
    public static let OP_NOT: UInt8 = 0x91
    public static let OP_0NOTEQUAL: UInt8 = 0x92
    public static let OP_ADD: UInt8 = 0x93
    public static let OP_SUB: UInt8 = 0x94
    public static let OP_MUL: UInt8 = 0x95
    public static let OP_DIV: UInt8 = 0x96
    public static let OP_MOD: UInt8 = 0x97
    public static let OP_LSHIFT: UInt8 = 0x98
    public static let OP_RSHIFT: UInt8 = 0x99
    public static let OP_BOOLAND: UInt8 = 0x9a
    public static let OP_BOOLOR: UInt8 = 0x9b
    public static let OP_NUMEQUAL: UInt8 = 0x9c
    public static let OP_NUMEQUALVERIFY: UInt8 = 0x9d
    public static let OP_NUMNOTEQUAL: UInt8 = 0x9e
    public static let OP_LESSTHAN: UInt8 = 0x9f
    public static let OP_GREATERTHAN: UInt8 = 0xa0
    public static let OP_LESSTHANOREQUAL: UInt8 = 0xa1
    public static let OP_GREATERTHANOREQUAL: UInt8 = 0xa2
    public static let OP_MIN: UInt8 = 0xa3
    public static let OP_MAX: UInt8 = 0xa4
    public static let OP_WITHIN: UInt8 = 0xa5

    // MARK: - Crypto

    public static let OP_RIPEMD160: UInt8 = 0xa6
    public static let OP_SHA1: UInt8 = 0xa7
    public static let OP_SHA256: UInt8 = 0xa8
    public static let OP_HASH160: UInt8 = 0xa9
    public static let OP_HASH256: UInt8 = 0xaa
    public static let OP_CODESEPARATOR: UInt8 = 0xab
    public static let OP_CHECKSIG: UInt8 = 0xac
    public static let OP_CHECKSIGVERIFY: UInt8 = 0xad
    public static let OP_CHECKMULTISIG: UInt8 = 0xae
    public static let OP_CHECKMULTISIGVERIFY: UInt8 = 0xaf

    // MARK: - Locktime

    public static let OP_NOP1: UInt8 = 0xb0
    public static let OP_NOP2: UInt8 = 0xb1
    public static let OP_CHECKLOCKTIMEVERIFY: UInt8 = 0xb1
    public static let OP_NOP3: UInt8 = 0xb2
    public static let OP_CHECKSEQUENCEVERIFY: UInt8 = 0xb2
    public static let OP_NOP4: UInt8 = 0xb3
    public static let OP_NOP5: UInt8 = 0xb4
    public static let OP_NOP6: UInt8 = 0xb5
    public static let OP_NOP7: UInt8 = 0xb6
    public static let OP_NOP8: UInt8 = 0xb7
    public static let OP_NOP9: UInt8 = 0xb8
    public static let OP_NOP10: UInt8 = 0xb9

    // MARK: - Unknown / Undefined (0xba - 0xf9)

    public static let OP_UNKNOWN186: UInt8 = 0xba
    public static let OP_UNKNOWN187: UInt8 = 0xbb
    public static let OP_UNKNOWN188: UInt8 = 0xbc
    public static let OP_UNKNOWN189: UInt8 = 0xbd
    public static let OP_UNKNOWN190: UInt8 = 0xbe
    public static let OP_UNKNOWN191: UInt8 = 0xbf
    public static let OP_UNKNOWN192: UInt8 = 0xc0
    public static let OP_UNKNOWN193: UInt8 = 0xc1
    public static let OP_UNKNOWN194: UInt8 = 0xc2
    public static let OP_UNKNOWN195: UInt8 = 0xc3
    public static let OP_UNKNOWN196: UInt8 = 0xc4
    public static let OP_UNKNOWN197: UInt8 = 0xc5
    public static let OP_UNKNOWN198: UInt8 = 0xc6
    public static let OP_UNKNOWN199: UInt8 = 0xc7
    public static let OP_UNKNOWN200: UInt8 = 0xc8
    public static let OP_UNKNOWN201: UInt8 = 0xc9
    public static let OP_UNKNOWN202: UInt8 = 0xca
    public static let OP_UNKNOWN203: UInt8 = 0xcb
    public static let OP_UNKNOWN204: UInt8 = 0xcc
    public static let OP_UNKNOWN205: UInt8 = 0xcd
    public static let OP_UNKNOWN206: UInt8 = 0xce
    public static let OP_UNKNOWN207: UInt8 = 0xcf
    public static let OP_UNKNOWN208: UInt8 = 0xd0
    public static let OP_UNKNOWN209: UInt8 = 0xd1
    public static let OP_UNKNOWN210: UInt8 = 0xd2
    public static let OP_UNKNOWN211: UInt8 = 0xd3
    public static let OP_UNKNOWN212: UInt8 = 0xd4
    public static let OP_UNKNOWN213: UInt8 = 0xd5
    public static let OP_UNKNOWN214: UInt8 = 0xd6
    public static let OP_UNKNOWN215: UInt8 = 0xd7
    public static let OP_UNKNOWN216: UInt8 = 0xd8
    public static let OP_UNKNOWN217: UInt8 = 0xd9
    public static let OP_UNKNOWN218: UInt8 = 0xda
    public static let OP_UNKNOWN219: UInt8 = 0xdb
    public static let OP_UNKNOWN220: UInt8 = 0xdc
    public static let OP_UNKNOWN221: UInt8 = 0xdd
    public static let OP_UNKNOWN222: UInt8 = 0xde
    public static let OP_UNKNOWN223: UInt8 = 0xdf
    public static let OP_UNKNOWN224: UInt8 = 0xe0
    public static let OP_UNKNOWN225: UInt8 = 0xe1
    public static let OP_UNKNOWN226: UInt8 = 0xe2
    public static let OP_UNKNOWN227: UInt8 = 0xe3
    public static let OP_UNKNOWN228: UInt8 = 0xe4
    public static let OP_UNKNOWN229: UInt8 = 0xe5
    public static let OP_UNKNOWN230: UInt8 = 0xe6
    public static let OP_UNKNOWN231: UInt8 = 0xe7
    public static let OP_UNKNOWN232: UInt8 = 0xe8
    public static let OP_UNKNOWN233: UInt8 = 0xe9
    public static let OP_UNKNOWN234: UInt8 = 0xea
    public static let OP_UNKNOWN235: UInt8 = 0xeb
    public static let OP_UNKNOWN236: UInt8 = 0xec
    public static let OP_UNKNOWN237: UInt8 = 0xed
    public static let OP_UNKNOWN238: UInt8 = 0xee
    public static let OP_UNKNOWN239: UInt8 = 0xef
    public static let OP_UNKNOWN240: UInt8 = 0xf0
    public static let OP_UNKNOWN241: UInt8 = 0xf1
    public static let OP_UNKNOWN242: UInt8 = 0xf2
    public static let OP_UNKNOWN243: UInt8 = 0xf3
    public static let OP_UNKNOWN244: UInt8 = 0xf4
    public static let OP_UNKNOWN245: UInt8 = 0xf5
    public static let OP_UNKNOWN246: UInt8 = 0xf6
    public static let OP_UNKNOWN247: UInt8 = 0xf7
    public static let OP_UNKNOWN248: UInt8 = 0xf8
    public static let OP_UNKNOWN249: UInt8 = 0xf9

    // MARK: - Bitcoin Core Internal

    public static let OP_SMALLINTEGER: UInt8 = 0xfa
    public static let OP_PUBKEYS: UInt8 = 0xfb
    public static let OP_UNKNOWN252: UInt8 = 0xfc
    public static let OP_PUBKEYHASH: UInt8 = 0xfd
    public static let OP_PUBKEY: UInt8 = 0xfe
    public static let OP_INVALIDOPCODE: UInt8 = 0xff

    // MARK: - Name Lookup

    /// Map from opcode byte value to its canonical string name.
    /// For ASM representation and debugging.
    public static func name(for opcode: UInt8) -> String {
        if let name = opcodeNames[opcode] {
            return name
        }
        return "OP_UNKNOWN\(opcode)"
    }

    /// Map from string name to opcode byte value.
    /// Used for ASM parsing.
    public static func code(for name: String) -> UInt8? {
        return nameToOpcode[name]
    }

    /// Whether the opcode is a direct data push (0x01-0x4b).
    public static func isDataPush(_ opcode: UInt8) -> Bool {
        return opcode >= 0x01 && opcode <= 0x4b
    }

    /// Whether the opcode pushes a small integer (OP_0 or OP_1 through OP_16).
    public static func isSmallInt(_ opcode: UInt8) -> Bool {
        return opcode == OP_0 || (opcode >= OP_1 && opcode <= OP_16)
    }

    /// Return the small integer value for OP_0 through OP_16, or nil.
    public static func smallIntValue(_ opcode: UInt8) -> Int? {
        if opcode == OP_0 { return 0 }
        if opcode >= OP_1 && opcode <= OP_16 {
            return Int(opcode) - Int(OP_1) + 1
        }
        return nil
    }

    // MARK: - Private Lookup Tables

    private static let opcodeNames: [UInt8: String] = {
        var map = [UInt8: String]()
        map[0x00] = "OP_0"
        for i: UInt8 in 0x01...0x4b {
            map[i] = "OP_DATA_\(i)"
        }
        map[0x4c] = "OP_PUSHDATA1"
        map[0x4d] = "OP_PUSHDATA2"
        map[0x4e] = "OP_PUSHDATA4"
        map[0x4f] = "OP_1NEGATE"
        map[0x50] = "OP_RESERVED"
        map[0x51] = "OP_1"
        map[0x52] = "OP_2"
        map[0x53] = "OP_3"
        map[0x54] = "OP_4"
        map[0x55] = "OP_5"
        map[0x56] = "OP_6"
        map[0x57] = "OP_7"
        map[0x58] = "OP_8"
        map[0x59] = "OP_9"
        map[0x5a] = "OP_10"
        map[0x5b] = "OP_11"
        map[0x5c] = "OP_12"
        map[0x5d] = "OP_13"
        map[0x5e] = "OP_14"
        map[0x5f] = "OP_15"
        map[0x60] = "OP_16"
        map[0x61] = "OP_NOP"
        map[0x62] = "OP_VER"
        map[0x63] = "OP_IF"
        map[0x64] = "OP_NOTIF"
        map[0x65] = "OP_VERIF"
        map[0x66] = "OP_VERNOTIF"
        map[0x67] = "OP_ELSE"
        map[0x68] = "OP_ENDIF"
        map[0x69] = "OP_VERIFY"
        map[0x6a] = "OP_RETURN"
        map[0x6b] = "OP_TOALTSTACK"
        map[0x6c] = "OP_FROMALTSTACK"
        map[0x6d] = "OP_2DROP"
        map[0x6e] = "OP_2DUP"
        map[0x6f] = "OP_3DUP"
        map[0x70] = "OP_2OVER"
        map[0x71] = "OP_2ROT"
        map[0x72] = "OP_2SWAP"
        map[0x73] = "OP_IFDUP"
        map[0x74] = "OP_DEPTH"
        map[0x75] = "OP_DROP"
        map[0x76] = "OP_DUP"
        map[0x77] = "OP_NIP"
        map[0x78] = "OP_OVER"
        map[0x79] = "OP_PICK"
        map[0x7a] = "OP_ROLL"
        map[0x7b] = "OP_ROT"
        map[0x7c] = "OP_SWAP"
        map[0x7d] = "OP_TUCK"
        map[0x7e] = "OP_CAT"
        map[0x7f] = "OP_SPLIT"
        map[0x80] = "OP_NUM2BIN"
        map[0x81] = "OP_BIN2NUM"
        map[0x82] = "OP_SIZE"
        map[0x83] = "OP_INVERT"
        map[0x84] = "OP_AND"
        map[0x85] = "OP_OR"
        map[0x86] = "OP_XOR"
        map[0x87] = "OP_EQUAL"
        map[0x88] = "OP_EQUALVERIFY"
        map[0x89] = "OP_RESERVED1"
        map[0x8a] = "OP_RESERVED2"
        map[0x8b] = "OP_1ADD"
        map[0x8c] = "OP_1SUB"
        map[0x8d] = "OP_2MUL"
        map[0x8e] = "OP_2DIV"
        map[0x8f] = "OP_NEGATE"
        map[0x90] = "OP_ABS"
        map[0x91] = "OP_NOT"
        map[0x92] = "OP_0NOTEQUAL"
        map[0x93] = "OP_ADD"
        map[0x94] = "OP_SUB"
        map[0x95] = "OP_MUL"
        map[0x96] = "OP_DIV"
        map[0x97] = "OP_MOD"
        map[0x98] = "OP_LSHIFT"
        map[0x99] = "OP_RSHIFT"
        map[0x9a] = "OP_BOOLAND"
        map[0x9b] = "OP_BOOLOR"
        map[0x9c] = "OP_NUMEQUAL"
        map[0x9d] = "OP_NUMEQUALVERIFY"
        map[0x9e] = "OP_NUMNOTEQUAL"
        map[0x9f] = "OP_LESSTHAN"
        map[0xa0] = "OP_GREATERTHAN"
        map[0xa1] = "OP_LESSTHANOREQUAL"
        map[0xa2] = "OP_GREATERTHANOREQUAL"
        map[0xa3] = "OP_MIN"
        map[0xa4] = "OP_MAX"
        map[0xa5] = "OP_WITHIN"
        map[0xa6] = "OP_RIPEMD160"
        map[0xa7] = "OP_SHA1"
        map[0xa8] = "OP_SHA256"
        map[0xa9] = "OP_HASH160"
        map[0xaa] = "OP_HASH256"
        map[0xab] = "OP_CODESEPARATOR"
        map[0xac] = "OP_CHECKSIG"
        map[0xad] = "OP_CHECKSIGVERIFY"
        map[0xae] = "OP_CHECKMULTISIG"
        map[0xaf] = "OP_CHECKMULTISIGVERIFY"
        map[0xb0] = "OP_NOP1"
        map[0xb1] = "OP_NOP2"
        map[0xb2] = "OP_NOP3"
        map[0xb3] = "OP_NOP4"
        map[0xb4] = "OP_NOP5"
        map[0xb5] = "OP_NOP6"
        map[0xb6] = "OP_NOP7"
        map[0xb7] = "OP_NOP8"
        map[0xb8] = "OP_NOP9"
        map[0xb9] = "OP_NOP10"
        for i: UInt8 in 0xba...0xf9 {
            map[i] = "OP_UNKNOWN\(i)"
        }
        map[0xfa] = "OP_SMALLINTEGER"
        map[0xfb] = "OP_PUBKEYS"
        map[0xfc] = "OP_UNKNOWN252"
        map[0xfd] = "OP_PUBKEYHASH"
        map[0xfe] = "OP_PUBKEY"
        map[0xff] = "OP_INVALIDOPCODE"
        return map
    }()

    private static let nameToOpcode: [String: UInt8] = {
        var map = [String: UInt8]()
        for (value, name) in opcodeNames {
            map[name] = value
        }
        // Add aliases
        map["OP_FALSE"] = OP_FALSE
        map["OP_TRUE"] = OP_TRUE
        map["OP_ZERO"] = OP_0
        map["OP_ONE"] = OP_1
        map["OP_CHECKLOCKTIMEVERIFY"] = OP_CHECKLOCKTIMEVERIFY
        map["OP_CHECKSEQUENCEVERIFY"] = OP_CHECKSEQUENCEVERIFY
        return map
    }()
}
