// SPDX-License-Identifier: Open BSV License Version 5
// Script execution stack: a sequence of byte buffers with a 1000-element limit.

import Foundation

/// A Bitcoin script execution stack.
///
/// Stores `Data` items. Underflow and overflow throw `ScriptError`. The
/// 1000-element limit is the post-genesis Bitcoin consensus rule and applies
/// to the combined main + alt stack size.
public struct ScriptStack {
    /// Maximum combined number of items across main + alt stack (consensus).
    public static let maxStackSize = 1000

    /// Main stack items.
    public private(set) var items: [Data] = []
    /// Alt stack items.
    public private(set) var altItems: [Data] = []

    public init() {}

    /// Combined size of main + alt stacks.
    public var combinedSize: Int { items.count + altItems.count }

    /// Number of items on the main stack.
    public var size: Int { items.count }

    /// Number of items on the alt stack.
    public var altSize: Int { altItems.count }

    /// Whether the main stack is empty.
    public var isEmpty: Bool { items.isEmpty }

    // MARK: - Main stack

    /// Push an item onto the main stack.
    public mutating func push(_ item: Data) throws {
        if combinedSize + 1 > Self.maxStackSize {
            throw ScriptError.stackOverflow("stack size exceeded \(Self.maxStackSize)")
        }
        items.append(item)
    }

    /// Pop the top item from the main stack.
    @discardableResult
    public mutating func pop() throws -> Data {
        guard let v = items.popLast() else {
            throw ScriptError.stackUnderflow("attempted to pop from empty stack")
        }
        return v
    }

    /// Peek at the main stack from the top.
    /// `index` 0 means top, 1 means second from top, etc.
    public func peek(_ index: Int = 0) throws -> Data {
        guard index >= 0, index < items.count else {
            throw ScriptError.stackUnderflow("peek index \(index) out of range (size \(items.count))")
        }
        return items[items.count - 1 - index]
    }

    /// Replace the item at depth `index` from the top.
    public mutating func replace(_ index: Int, with value: Data) throws {
        guard index >= 0, index < items.count else {
            throw ScriptError.stackUnderflow("replace index \(index) out of range (size \(items.count))")
        }
        items[items.count - 1 - index] = value
    }

    /// Remove the item at depth `index` from the top and return it.
    public mutating func remove(_ index: Int) throws -> Data {
        guard index >= 0, index < items.count else {
            throw ScriptError.stackUnderflow("remove index \(index) out of range (size \(items.count))")
        }
        return items.remove(at: items.count - 1 - index)
    }

    /// Insert a value at depth `index` from the top.
    /// `index` 0 means insert at the top.
    public mutating func insert(_ value: Data, at index: Int) throws {
        guard index >= 0, index <= items.count else {
            throw ScriptError.stackUnderflow("insert index \(index) out of range (size \(items.count))")
        }
        if combinedSize + 1 > Self.maxStackSize {
            throw ScriptError.stackOverflow("stack size exceeded \(Self.maxStackSize)")
        }
        items.insert(value, at: items.count - index)
    }

    // MARK: - Alt stack

    /// Push an item onto the alt stack.
    public mutating func pushAlt(_ item: Data) throws {
        if combinedSize + 1 > Self.maxStackSize {
            throw ScriptError.stackOverflow("alt stack size exceeded \(Self.maxStackSize)")
        }
        altItems.append(item)
    }

    /// Pop an item from the alt stack.
    @discardableResult
    public mutating func popAlt() throws -> Data {
        guard let v = altItems.popLast() else {
            throw ScriptError.invalidAltStack("attempted to pop from empty alt stack")
        }
        return v
    }
}
