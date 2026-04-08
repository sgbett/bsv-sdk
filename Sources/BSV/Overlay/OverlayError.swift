// SPDX-License-Identifier: Open BSV License Version 5
// Error cases raised by the overlay tools (SHIP broadcasters, lookup
// resolvers, and the overlay admin token template).

import Foundation

/// Errors raised by the overlay tools module.
public enum OverlayError: Error, LocalizedError, Equatable {
    /// A topic name did not start with the required `tm_` prefix.
    case invalidTopicPrefix(String)
    /// A lookup service name did not start with the required `ls_` prefix.
    case invalidServiceName(String)
    /// No SHIP/SLAP hosts were interested in the supplied topics or service.
    case noHostsInterested(String)
    /// The acknowledgment policy was violated by the gathered responses.
    case acknowledgmentFailure(String)
    /// The overlay advertisement token was structurally invalid.
    case invalidAdvertisement(String)
    /// A lookup response was malformed or unreadable.
    case invalidLookupResponse(String)
    /// The supplied URL could not be parsed.
    case invalidURL(String)
    /// A transport/network failure occurred.
    case networkFailure(String)
    /// An operation needed a property that was missing or malformed.
    case missingField(String)

    public var errorDescription: String? {
        switch self {
        case .invalidTopicPrefix(let topic):
            return "Invalid topic prefix (expected 'tm_'): \(topic)"
        case .invalidServiceName(let name):
            return "Invalid lookup service name (expected 'ls_' prefix): \(name)"
        case .noHostsInterested(let detail):
            return "No overlay hosts were interested: \(detail)"
        case .acknowledgmentFailure(let detail):
            return "Overlay acknowledgment failure: \(detail)"
        case .invalidAdvertisement(let detail):
            return "Invalid SHIP/SLAP advertisement: \(detail)"
        case .invalidLookupResponse(let detail):
            return "Invalid lookup response: \(detail)"
        case .invalidURL(let url):
            return "Invalid URL: \(url)"
        case .networkFailure(let detail):
            return "Overlay network failure: \(detail)"
        case .missingField(let field):
            return "Missing field: \(field)"
        }
    }
}
