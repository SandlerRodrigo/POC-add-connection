//
//  ConnectAll.swift
//  POC-add-connection
//
//  Created by Rodrigo Sandler on 03/11/25.
//

import SwiftUI
import MultipeerConnectivity
import CryptoKit
import Security
internal import Combine

// MARK: - Keychain Helper (simples)
enum KeychainHelper {
    static func save(_ data: Data, account: String, service: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    static func load(account: String, service: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        SecItemCopyMatching(query as CFDictionary, &item)
        return item as? Data
    }
}

// MARK: - Identidade do usuário (UUID persistido)
final class UserIdentifiers {
    static let shared = UserIdentifiers()
    private init() {
        if let data = KeychainHelper.load(account: "userId", service: "conn.app") {
            userId = String(decoding: data, as: UTF8.self)
        } else {
            let id = UUID().uuidString.lowercased()
            KeychainHelper.save(Data(id.utf8), account: "userId", service: "conn.app")
            userId = id
        }
    }
    let userId: String
}

// MARK: - Cripto helpers
enum CryptoHelpers {
    struct SigningKeys {
        let privateKey: Curve25519.Signing.PrivateKey
        var publicKey: Curve25519.Signing.PublicKey { privateKey.publicKey }
    }

    static func loadOrCreateKeys() -> SigningKeys {
        let svc = "conn.app", acc = "sk.signing"
        if let data = KeychainHelper.load(account: acc, service: svc),
           let pk = try? Curve25519.Signing.PrivateKey(rawRepresentation: data) {
            return SigningKeys(privateKey: pk)
        }
        let pk = Curve25519.Signing.PrivateKey()
        KeychainHelper.save(pk.rawRepresentation, account: acc, service: svc)
        return SigningKeys(privateKey: pk)
    }

    static func sha256Hex(_ data: Data) -> String {
        let hash = SHA256.hash(data: data)
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    static func pubKeyFingerprintHex(_ pubKey: Curve25519.Signing.PublicKey) -> String {
        sha256Hex(pubKey.rawRepresentation)
    }
}

// MARK: - Modelo do registro de conexão
struct ConnectionRecord: Codable, Identifiable {
    var id: String { connectionId }

    let connectionId: String
    let method: String
    let meUserId: String
    let peerUserId: String
    let peerDisplayName: String
    let peerPubKeyFingerprint: String
    let unixTs: Int
    let iso8601: String
    let timezoneSecondsFromGMT: Int

    init(method: String,
         meUserId: String,
         peerUserId: String,
         peerDisplayName: String,
         peerPubKeyFingerprint: String,
         timestamp: Date = Date()) {

        self.method = method
        self.meUserId = meUserId
        self.peerUserId = peerUserId
        self.peerDisplayName = peerDisplayName
        self.peerPubKeyFingerprint = peerPubKeyFingerprint

        let tz = TimeZone.current.secondsFromGMT()
        timezoneSecondsFromGMT = tz

        let ts = Int(timestamp.timeIntervalSince1970)
        unixTs = ts

        let fmt = ISO8601DateFormatter()
        fmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        iso8601 = fmt.string(from: timestamp)

        // connectionId = sha256( sort([me, peer]).join("|") + "|" + ts )
        let ordered = [meUserId, peerUserId].sorted().joined(separator: "|")
        let raw = Data("\(ordered)|\(ts)".utf8)
        connectionId = CryptoHelpers.sha256Hex(raw)
    }
}

// MARK: - Multipeer Manager (descoberta + troca de cartão)
final class MultipeerManager: NSObject, ObservableObject {
    static let serviceType = "conn-app" // <= 15 chars, [a-z0-9-]
    // identidades
    private let myPeerID = MCPeerID(displayName: UIDevice.current.name)
    private let session: MCSession
    private let advertiser: MCNearbyServiceAdvertiser
    private let browser: MCNearbyServiceBrowser

    // estado/UX
    @Published var foundPeers: [MCPeerID] = []
    @Published var lastConnection: ConnectionRecord?
    @Published var allConnections: [ConnectionRecord] = []

    // cripto/ids
    private let keys = CryptoHelpers.loadOrCreateKeys()
    private let userId = UserIdentifiers.shared.userId

    // nome exibido (UI controla)
    private var displayNameForCard: String = UIDevice.current.name

    override init() {
        session = MCSession(peer: myPeerID, securityIdentity: nil, encryptionPreference: .required)
        advertiser = MCNearbyServiceAdvertiser(peer: myPeerID, discoveryInfo: nil, serviceType: Self.serviceType)
        browser = MCNearbyServiceBrowser(peer: myPeerID, serviceType: Self.serviceType)
        super.init()
        session.delegate = self
        advertiser.delegate = self
        browser.delegate = self
    }

    func updateDisplayName(_ name: String) {
        displayNameForCard = name
    }

    func start() {
        advertiser.startAdvertisingPeer()
        browser.startBrowsingForPeers()
    }

    func stop() {
        advertiser.stopAdvertisingPeer()
        browser.stopBrowsingForPeers()
    }

    func invite(_ peer: MCPeerID) {
        browser.invitePeer(peer, to: session, withContext: nil, timeout: 10)
    }

    // envelope que trocamos
    struct Envelope: Codable {
        let payloadB64: String
        let signatureB64: String
    }

    private func makeEnvelope() throws -> Data {
        let pubKey = keys.privateKey.publicKey
        let obj: [String: Any] = [
            "userId": userId,
            "displayName": displayNameForCard,
            "pubKey": pubKey.rawRepresentation.base64EncodedString(),
            "pubKeyFingerprint": CryptoHelpers.pubKeyFingerprintHex(pubKey),
            "ts": Int(Date().timeIntervalSince1970)
        ]
        let json = try JSONSerialization.data(withJSONObject: obj)
        let sig = try keys.privateKey.signature(for: json)
        let env = Envelope(payloadB64: json.base64EncodedString(),
                           signatureB64: sig.base64EncodedString())
        return try JSONEncoder().encode(env)
    }

    private func sendMyCard(to peers: [MCPeerID]) {
        do {
            let data = try makeEnvelope()
            try session.send(data, toPeers: peers, with: .reliable)
        } catch {
            print("send error:", error)
        }
    }
}

// MARK: - Delegates
extension MultipeerManager: MCSessionDelegate, MCNearbyServiceAdvertiserDelegate, MCNearbyServiceBrowserDelegate {
    // mudanças de estado: quando conectar, envie meu cartão automaticamente
    func session(_ s: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        if state == .connected {
            sendMyCard(to: [peerID])
        }
    }

    // recebi dados (cartão do peer)
    func session(_ s: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        guard let env = try? JSONDecoder().decode(Envelope.self, from: data),
              let payload = Data(base64Encoded: env.payloadB64),
              let sig = Data(base64Encoded: env.signatureB64),
              let any = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let peerUserId = any["userId"] as? String,
              let peerDisplayName = any["displayName"] as? String,
              let pubKeyB64 = any["pubKey"] as? String,
              let pubKeyData = Data(base64Encoded: pubKeyB64),
              let fp = any["pubKeyFingerprint"] as? String
        else { return }

        // verificar assinatura usando a pubKey enviada
        guard let senderPub = try? Curve25519.Signing.PublicKey(rawRepresentation: pubKeyData),
              senderPub.isValidSignature(sig, for: payload) else {
            print("assinatura inválida")
            return
        }

        // criar registro do momento
        let rec = ConnectionRecord(
            method: "multipeer",
            meUserId: UserIdentifiers.shared.userId,
            peerUserId: peerUserId,
            peerDisplayName: peerDisplayName,
            peerPubKeyFingerprint: fp,
            timestamp: Date()
        )

        DispatchQueue.main.async {
            self.lastConnection = rec
            self.allConnections.insert(rec, at: 0)
            // debug: imprimir JSON no console
            if let json = try? JSONEncoder().encode(rec),
               let s = String(data: json, encoding: .utf8) {
                print("ConnectionRecord JSON:", s)
            }
        }
    }

    // não usados aqui
    func session(_ s: MCSession, didReceive stream: InputStream, withName: String, fromPeer: MCPeerID) {}
    func session(_ s: MCSession, didStartReceivingResourceWithName: String, fromPeer: MCPeerID, with: Progress) {}
    func session(_ s: MCSession, didFinishReceivingResourceWithName: String, fromPeer: MCPeerID, at: URL?, withError: Error?) {}

    // convite recebido (aqui já aceitamos automaticamente; em produção, mostre UI)
    func advertiser(_ a: MCNearbyServiceAdvertiser,
                    didReceiveInvitationFromPeer peerID: MCPeerID,
                    withContext context: Data?,
                    invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        invitationHandler(true, self.session)
    }

    // peers encontrados/perdidos
    func browser(_ b: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID, withDiscoveryInfo info: [String : String]?) {
        DispatchQueue.main.async {
            if !self.foundPeers.contains(peerID) { self.foundPeers.append(peerID) }
        }
    }
    func browser(_ b: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {
        DispatchQueue.main.async {
            self.foundPeers.removeAll { $0 == peerID }
        }
    }
}

// MARK: - UI simples
struct AddConnectionView: View {
    @StateObject private var mp = MultipeerManager()
    @State private var displayName = "Seu Nome"

    var body: some View {
        NavigationView {
            VStack(spacing: 16) {
                TextField("Nome exibido", text: $displayName)
                    .textFieldStyle(.roundedBorder)
                    .onChange(of: displayName) { mp.updateDisplayName($0) }
                    .onAppear { mp.updateDisplayName(displayName) }

                HStack {
                    Button("Procurar peers") { mp.start() }
                    Button("Parar") { mp.stop() }
                }

                List {
                    Section("Dispositivos próximos") {
                        if mp.foundPeers.isEmpty {
                            Text("Procurando... abra o app no outro iPhone e toque 'Procurar peers'.")
                                .foregroundColor(.secondary)
                        }
                        ForEach(mp.foundPeers, id: \.self) { peer in
                            HStack {
                                Text(peer.displayName)
                                Spacer()
                                Button("Convidar") { mp.invite(peer) }
                            }
                        }
                    }

                    Section("Últimas conexões") {
                        if mp.allConnections.isEmpty {
                            Text("Sem conexões ainda").foregroundColor(.secondary)
                        } else {
                            ForEach(mp.allConnections) { rec in
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(rec.peerDisplayName).font(.headline)
                                    Text("peerUserId: \(rec.peerUserId)").font(.footnote).foregroundColor(.secondary)
                                    Text("connectionId: \(rec.connectionId)").font(.footnote).foregroundColor(.secondary)
                                    Text("quando: \(rec.iso8601)  (UTC offset \(rec.timezoneSecondsFromGMT/3600)h)")
                                        .font(.footnote).foregroundColor(.secondary)
                                }
                                .padding(.vertical, 4)
                            }
                        }
                    }
                }
            }
            .padding()
            .navigationTitle("Add connection")
        }
    }
}
