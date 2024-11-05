//
//  Created by Aung Ko Min on 10/01/2021.
//

import Foundation
import CryptoKit

public extension Curve25519.KeyAgreement.PublicKey {
    var toBase64String: String { Cryptor.base64String(with: self) }
}
public extension String {
    var toPublicKey: Curve25519.KeyAgreement.PublicKey? { Cryptor.publicKey(with: self) }
}
