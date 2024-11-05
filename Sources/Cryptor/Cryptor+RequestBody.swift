//
//  Created by Aung Ko Min on 10/01/2021.
//

import Foundation
import CryptoKit
 
public extension Cryptor {

    fileprivate static func toJSON<T:Codable>(some : T) -> String? {
        guard let data = try? JSONEncoder().encode(some.self) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    struct StringRequestBody: Codable {
        public let secret: String
        public init(secret: String) {
            // param [secret] should allready be encrypted
            self.secret = secret
        }
    }
    
    struct DataRequestBody: Codable {
        public let secret: Data
        public init(secret: Data) {
            // param [secret] should allready be encrypted
            self.secret = secret
        }
    }
}
 
public extension Cryptor.StringRequestBody {
    var toJSON: String? { return Cryptor.toJSON(some: self) }
}

public extension Cryptor.DataRequestBody {
    
    var toJSON: String? { return Cryptor.toJSON(some: self) }

    // Maps a [DataRequestBody] into a [StringRequestBody]
    var toStringRequestBody: Cryptor.StringRequestBody {
        let secret = Cryptor.encondeForNetworkTransport(encrypted: self.secret)
        return Cryptor.StringRequestBody(secret: secret)
    }
    
}

