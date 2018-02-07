import Cryptor
import func Evergreen.getLogger
import Foundation
import SRP

#if os(Linux)
    import Dispatch
#endif

fileprivate let logger = getLogger("hap.pairSetup")
fileprivate typealias Session = PairSetupController.Session
fileprivate let SESSION_KEY = "hap.pair-setup.session"
fileprivate enum Error: Swift.Error {
    case noSession
}

func pairSetup(device: Device) -> Application {
    let group = Group.N3072
    let algorithm = Digest.Algorithm.sha512

    let username = "Pair-Setup"

    var timeOut = true

    func notifyPairingEvent(_ event: PairingEvent) {
        switch event {
        case .pairingStarted:
            DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(20)) {
                if timeOut {
                    timeOut = false
                    notifyPairingEvent(.pairingTimeout)
                }
            }
            timeOut = true
        case .pairingCompleted, .pairingFailed:
            timeOut = false
        default:
            break
        }
        device.notifyPairingEvent(event)
    }

    let (salt, verificationKey) = createSaltedVerificationKey(username: username,
                                                              password: device.setupCode,
                                                              group: group,
                                                              algorithm: algorithm)
    let controller = PairSetupController(device: device)
    func createSession() -> Session {
        return Session(server: SRP.Server(username: username,
                                          salt: salt,
                                          verificationKey: verificationKey,
                                          group: group,
                                          algorithm: algorithm))
    }
    func getSession(_ connection: Server.Connection) throws -> Session {
        guard let session = connection.context[SESSION_KEY] as? Session else {
            throw Error.noSession
        }
        return session
    }

    return { connection, request in
        var body = Data()
        guard
            (try? request.readAllData(into: &body)) != nil,
            let data: PairTagTLV8 = try? decode(body),
            let sequence = data[.state]?.first.flatMap({ PairSetupStep(rawValue: $0) })
        else {
            return .badRequest
        }
        let response: PairTagTLV8?
        do {
            switch sequence {
            case .startRequest:
                notifyPairingEvent(.pairingStarted)
                let session = createSession()
                response = try controller.startRequest(data, session)
                connection.context[SESSION_KEY] = session
            case .verifyRequest:
                let session = try getSession(connection)
                response = controller.verifyRequest(data, session)
                if let r = response, r[.error] != nil {
                    notifyPairingEvent(.pairingFailed)
                } else {
                    notifyPairingEvent(.pairingVerified)
                }
            case .keyExchangeRequest:
                let session = try getSession(connection)
                response = try controller.keyExchangeRequest(data, session)
                notifyPairingEvent(.pairingCompleted)
            default:
                response = nil
            }
        } catch {
            logger.warning(error)
            connection.context[SESSION_KEY] = nil
            response = nil
        }
        if let response = response {
            return Response(status: .ok, data: encode(response), mimeType: "application/pairing+tlv8")
        } else {
            // TODO: return error code -- otherwise setup will hang in iOS (spinner)
            notifyPairingEvent(.pairingFailed)
            return .badRequest
        }
    }
}
