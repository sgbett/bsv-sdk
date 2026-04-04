import Foundation

extension Data {
    /// Initialise `Data` from a hexadecimal string.
    ///
    /// Returns `nil` when the string contains non-hex characters.
    /// Odd-length strings are treated as if prefixed with a leading zero.
    public init?(hex: String) {
        var hexString = hex

        // Strip optional "0x" prefix
        if hexString.hasPrefix("0x") || hexString.hasPrefix("0X") {
            hexString = String(hexString.dropFirst(2))
        }

        // Pad odd-length strings with a leading zero
        if hexString.count % 2 != 0 {
            hexString = "0" + hexString
        }

        var data = Data(capacity: hexString.count / 2)
        var index = hexString.startIndex

        while index < hexString.endIndex {
            let nextIndex = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<nextIndex], radix: 16) else {
                return nil
            }
            data.append(byte)
            index = nextIndex
        }

        self = data
    }

    /// The lowercase hexadecimal representation of this data.
    public var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
