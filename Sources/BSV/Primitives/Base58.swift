import Foundation

/// Base58 and Base58Check encoding/decoding using the Bitcoin alphabet.
public enum Base58 {

    private static let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private static let base = 58

    // Reverse lookup table: ASCII value → alphabet index (255 = invalid)
    private static let decodeTable: [UInt8] = {
        var table = [UInt8](repeating: 255, count: 128)
        for (index, char) in alphabet.utf8.enumerated() {
            table[Int(char)] = UInt8(index)
        }
        return table
    }()

    // MARK: - Base58

    /// Encode binary data to a Base58 string.
    public static func encode(_ data: Data) -> String {
        // Count leading zero bytes — each becomes a '1' character
        let leadingZeros = data.prefix(while: { $0 == 0 }).count

        // Convert to base58 using repeated division
        var bytes = Array(data.dropFirst(leadingZeros))
        var result: [UInt8] = []

        while !bytes.isEmpty {
            var carry = 0
            var newBytes: [UInt8] = []
            for byte in bytes {
                carry = carry * 256 + Int(byte)
                if !newBytes.isEmpty || carry / base > 0 {
                    newBytes.append(UInt8(carry / base))
                }
                carry %= base
            }
            result.append(UInt8(carry))
            bytes = newBytes
        }

        // Build the output string: leading '1's + reversed base58 digits
        let prefix = String(repeating: "1", count: leadingZeros)
        let alphabetArray = Array(alphabet.utf8)
        let encoded = result.reversed().map { alphabetArray[Int($0)] }
        return prefix + String(bytes: encoded, encoding: .utf8)!
    }

    /// Decode a Base58 string to binary data.
    ///
    /// Returns `nil` if the string contains invalid characters.
    public static func decode(_ string: String) -> Data? {
        let utf8 = Array(string.utf8)

        // Count leading '1' characters — each becomes a 0x00 byte
        let leadingOnes = utf8.prefix(while: { $0 == UInt8(ascii: "1") }).count

        // Convert from base58 using the reverse lookup
        var result: [UInt8] = []
        for char in utf8 {
            guard char < 128 else { return nil }
            let value = decodeTable[Int(char)]
            guard value != 255 else { return nil }

            var carry = Int(value)
            for i in stride(from: result.count - 1, through: 0, by: -1) {
                carry += Int(result[i]) * base
                result[i] = UInt8(carry & 0xff)
                carry >>= 8
            }
            while carry > 0 {
                result.insert(UInt8(carry & 0xff), at: 0)
                carry >>= 8
            }
        }

        let leadingZeros = [UInt8](repeating: 0, count: leadingOnes)
        return Data(leadingZeros + result)
    }

    // MARK: - Base58Check

    /// Encode data with a 4-byte SHA-256d checksum appended, then Base58 encode.
    public static func checkEncode(_ data: Data) -> String {
        let checksum = Digest.sha256d(data).prefix(4)
        return encode(data + checksum)
    }

    /// Decode a Base58Check string. Verifies and strips the 4-byte checksum.
    ///
    /// Returns `nil` if decoding fails or the checksum does not match.
    public static func checkDecode(_ string: String) -> Data? {
        guard let decoded = decode(string), decoded.count >= 4 else {
            return nil
        }
        let payload = decoded.dropLast(4)
        let checksum = decoded.suffix(4)
        let expectedChecksum = Digest.sha256d(Data(payload)).prefix(4)
        guard checksum == expectedChecksum else {
            return nil
        }
        return Data(payload)
    }
}
