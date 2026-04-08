// SPDX-License-Identifier: Open BSV License Version 5
// Script interpreter error types.

import Foundation

/// Errors thrown during script interpretation.
public enum ScriptError: Error, Equatable {
    case stackUnderflow(String)
    case stackOverflow(String)
    case invalidOpcode(String)
    case disabledOpcode(String)
    case nonMinimalPush(String)
    case nonMinimalNumber(String)
    case invalidNumberRange(String)
    case verifyFailed(String)
    case unbalancedConditional(String)
    case cleanStack(String)
    case emptyStack(String)
    case falseStackTop(String)
    case scriptSize(String)
    case opCount(String)
    case pushSize(String)
    case pushOnly(String)
    case invalidSignature(String)
    case invalidPublicKey(String)
    case invalidSplitRange(String)
    case invalidOperandSize(String)
    case divisionByZero(String)
    case negativeShift(String)
    case numberOverflow(String)
    case invalidAltStack(String)
    case generic(String)
}
