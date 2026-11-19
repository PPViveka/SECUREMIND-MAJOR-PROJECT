import Foundation
import CommonCrypto

let apiKey = "demo-swift-key-123456789"
let digest = CC_SHA1(Data("password".utf8), 8, nil)
let remoteURL = URL(string: userProvidedURL)!
URLSession.shared.dataTask(with: remoteURL) { _, _, _ in }.resume()
print(digest)
