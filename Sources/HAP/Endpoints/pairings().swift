import Foundation
import func Evergreen.getLogger

fileprivate let logger = getLogger("hap.endpoints.pairings")

func pairings(device: Device) -> Application {
    return { connection, request in
        var body = Data()
        guard request.method == "POST" else {
            return .methodNotAllowed
        }
        guard
            (try? request.readAllData(into: &body)) != nil,
            let data: PairTagTLV8 = try? decode(body),
            data[.state]?[0] == PairStep.request.rawValue,
            let method = data[.pairingMethod].flatMap({ PairingMethod(rawValue: $0[0]) }),
            let username = data[.identifier]
            else {
                return .badRequest
        }

        guard connection.pairing?.role == .admin else {
            logger.warning("Permission denied (non-admin) to update pairing data: \(data), method: \(method)")
            let result: PairTagTLV8 = [
                (.state, Data(bytes: [PairStep.response.rawValue])),
                (.error, Data(bytes: [PairError.authenticationFailed.rawValue]))
            ]
            return Response(status: .ok, data: encode(result), mimeType: "application/pairing+tlv8")
        }

        logger.debug("Updating pairings data: \(data), method: \(method)")

        switch method {
        case .addPairing:
            guard let publicKey = data[.publicKey],
                let permissions = data[.permissions]?.first,
                let role = Pairing.Role(rawValue: permissions) else {
                    return .badRequest
            }
            device.add(pairing: Pairing(identifier: username, publicKey: publicKey, role: role))
            logger.info("Added \(role) pairing for \(String(data: username, encoding: .utf8)!)")
        case .removePairing:
            device.remove(pairingWithIdentifier: username)
            logger.info("Removed pairing for \(String(data: username, encoding: .utf8)!)")
        case .listPairings:
            logger.debug("Listing parings")
            let pairings = device.configuration.pairings.values
                .map { pairing -> PairTagTLV8 in
                    [
                        (.identifier, pairing.identifier),
                        (.publicKey, pairing.publicKey),
                        (.permissions, Data(bytes: [pairing.role.rawValue]))
                    ]
                }
                .joined(separator: [(.state, Data(bytes: [PairStep.response.rawValue]))])
                .flatMap { $0 }
            let results: PairTagTLV8 = [(.state, Data(bytes: [PairStep.response.rawValue]))] + pairings
            return Response(status: .ok, data: encode(results), mimeType: "application/pairing+tlv8")
        default:
            logger.info("Unhandled PairingMethod request: \(method)")
            return .badRequest
        }

        let result: PairTagTLV8 = [
            (.state, Data(bytes: [PairStep.response.rawValue]))
        ]
        return Response(status: .ok, data: encode(result), mimeType: "application/pairing+tlv8")
    }
}
