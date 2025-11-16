// VDB API Testing - AWS SigV4 Authentication Example (Swift for iOS)
// This example uses the AWS SDK for Swift via CocoaPods

// MARK: - Step 1: Installation
// Add to your Podfile:
// pod 'AWSCore', '~> 2.33'
// pod 'AWSCognito', '~> 2.33'
//
// Then run: pod install

// MARK: - Step 2: Import Required Frameworks
import Foundation
import AWSCore
import CommonCrypto

// MARK: - Step 3: Configuration - Set your Organization credentials
let VVD_ORG = "f7c11fc1-d422-4242-a05e-ea3e747b07bc" // Organization UUID (used as access key)
let VVD_SECRET = "ldCTA9jeOLtHdkByhLl8DyIIo5bd2Meb6IA4rATn0KCanfzU2s97CTBQ7bxtYTIs" // Organization Secret (64 chars)
let VVD_ACCESS_KEY = VVD_ORG // Access key is the Organization UUID

// MARK: - Step 4: AWS SigV4 Signing Helper Functions
extension String {
    func sha512() -> String {
        guard let data = self.data(using: .utf8) else { return "" }
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA512($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    func hmacSHA512(key: String) -> Data {
        let keyData = key.data(using: .utf8)!
        let messageData = self.data(using: .utf8)!
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        keyData.withUnsafeBytes { keyBytes in
            messageData.withUnsafeBytes { messageBytes in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA512),
                       keyBytes.baseAddress, keyData.count,
                       messageBytes.baseAddress, messageData.count,
                       &hash)
            }
        }
        return Data(hash)
    }
    
    func hmacSHA512(key: Data) -> Data {
        let messageData = self.data(using: .utf8)!
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        key.withUnsafeBytes { keyBytes in
            messageData.withUnsafeBytes { messageBytes in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA512),
                       keyBytes.baseAddress, key.count,
                       messageBytes.baseAddress, messageData.count,
                       &hash)
            }
        }
        return Data(hash)
    }
}

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Step 5: AWS SigV4 Request Signer
class AWSV4Signer {
    static func signRequest(
        accessKey: String,
        secretKey: String,
        method: String,
        path: String,
        headers: [String: String] = [:],
        body: String = ""
    ) -> [String: String] {
        let region = "us-east-1"
        let service = "vdb"
        
        // Generate timestamp
        let dateFormatter = DateFormatter()
        dateFormatter.timeZone = TimeZone(abbreviation: "UTC")
        dateFormatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        let amzDate = dateFormatter.string(from: Date())
        
        dateFormatter.dateFormat = "yyyyMMdd"
        let dateStamp = dateFormatter.string(from: Date())
        
        // Add required headers
        var allHeaders = headers
        allHeaders["x-amz-date"] = amzDate
        
        // Create canonical request
        let payloadHash = body.sha512()
        let signedHeaders = allHeaders.keys.sorted().joined(separator: ";")
        let canonicalHeaders = allHeaders.keys.sorted()
            .map { "\($0):\(allHeaders[$0]!.trimmingCharacters(in: .whitespaces))\n" }
            .joined()
        
        let canonicalRequest = [
            method,
            path,
            "", // query string
            canonicalHeaders,
            signedHeaders,
            payloadHash
        ].joined(separator: "\n")
        
        // Create string to sign
        let canonicalRequestHash = canonicalRequest.sha512()
        let credentialScope = "\(dateStamp)/\(region)/\(service)/aws4_request"
        let stringToSign = [
            "AWS4-HMAC-SHA512",
            amzDate,
            credentialScope,
            canonicalRequestHash
        ].joined(separator: "\n")
        
        // Calculate signature
        let kDate = dateStamp.hmacSHA512(key: "AWS4\(secretKey)")
        let kRegion = region.hmacSHA512(key: kDate)
        let kService = service.hmacSHA512(key: kRegion)
        let kSigning = "aws4_request".hmacSHA512(key: kService)
        let signature = stringToSign.hmacSHA512(key: kSigning).hexEncodedString()
        
        // Build authorization header
        let authHeader = "AWS4-HMAC-SHA512 Credential=\(accessKey)/\(credentialScope), SignedHeaders=\(signedHeaders), Signature=\(signature)"
        
        var signedHeaders = allHeaders
        signedHeaders["Authorization"] = authHeader
        
        return signedHeaders
    }
}

// MARK: - Step 6: VDB API Client
class VDBAPIClient {
    private let accessKey: String
    private let secretKey: String
    private let baseURL = "https://api.vdb.vulnetix.com/v1"
    
    init(accessKey: String, secretKey: String) {
        self.accessKey = accessKey
        self.secretKey = secretKey
    }
    
    // Get JWT token from /v1/auth/token
    func getJWTToken(completion: @escaping (Result<String, Error>) -> Void) {
        let method = "GET"
        let path = "/auth/token"
        
        // Sign the request
        let signedHeaders = AWSV4Signer.signRequest(
            accessKey: accessKey,
            secretKey: secretKey,
            method: method,
            path: path
        )
        
        // Create URL request
        guard let url = URL(string: "\(baseURL)\(path)") else {
            completion(.failure(NSError(domain: "VDBAPIClient", code: -1, 
                userInfo: [NSLocalizedDescriptionKey: "Invalid URL"])))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = method
        
        // Add signed headers
        for (key, value) in signedHeaders {
            request.setValue(value, forHTTPHeaderField: key)
        }
        
        // Make the request
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let data = data else {
                completion(.failure(NSError(domain: "VDBAPIClient", code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "No data received"])))
                return
            }
            
            do {
                if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let token = json["token"] as? String {
                    print("JWT token obtained (expires in 15 minutes): \(token.prefix(50))...")
                    if let exp = json["exp"] as? Int {
                        let expiryDate = Date(timeIntervalSince1970: TimeInterval(exp))
                        print("Token expires at: \(expiryDate)")
                    }
                    completion(.success(token))
                } else {
                    completion(.failure(NSError(domain: "VDBAPIClient", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "Failed to obtain JWT token"])))
                }
            } catch {
                completion(.failure(error))
            }
        }
        task.resume()
    }
    
    // Make GET request to /ecosystems
    func makeAPIRequest(jwtToken: String, completion: @escaping (Result<[String: Any], Error>) -> Void) {
        let method = "GET"
        let path = "/ecosystems"
        
        guard let url = URL(string: "\(baseURL)\(path)") else {
            completion(.failure(NSError(domain: "VDBAPIClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Invalid URL"])))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(jwtToken)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let data = data else {
                completion(.failure(NSError(domain: "VDBAPIClient", code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "No data received"])))
                return
            }
            
            do {
                if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    print("API Response: \(json)")
                    completion(.success(json))
                } else {
                    completion(.failure(NSError(domain: "VDBAPIClient", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "Invalid response format"])))
                }
            } catch {
                completion(.failure(error))
            }
        }
        task.resume()
    }
}

// MARK: - Step 7: Usage Example
// Initialize the API client
let client = VDBAPIClient(accessKey: VVD_ACCESS_KEY, secretKey: VVD_SECRET)

// Get JWT token and make API request
client.getJWTToken { result in
    switch result {
    case .success(let jwtToken):
        // Use the JWT token to make API requests
        client.makeAPIRequest(jwtToken: jwtToken) { result in
            switch result {
            case .success(let response):
                print("Success! Response: \(response)")
            case .failure(let error):
                print("API request failed: \(error.localizedDescription)")
            }
        }
    case .failure(let error):
        print("Failed to obtain JWT token: \(error.localizedDescription)")
    }
}
