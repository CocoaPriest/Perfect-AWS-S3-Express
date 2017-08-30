import cURL
import Foundation
import PerfectCrypto
import PerfectCURL
import PerfectLib
import PerfectThread

public struct AWS {
    
    public static var debug = false
    
    open class Access {
        let key : String
        let secret : String
        var timestamp = ""
        
        public func update() {
            let fmt = DateFormatter()
            fmt.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
            timestamp = fmt.string(from: Date())
        }
        public init(accessKey: String, accessSecret: String) {
            key = accessKey
            secret = accessSecret
            update()
        }
        
        public func signV4(_ string: String) -> String {
            var bytes = string.sign(.sha1, key: HMACKey(secret))?.encode(.base64)
            bytes?.append(0)
            if let b = bytes {
                return String(cString: b)
            } else {
                return ""
            }
        }
    }
    
    public enum Exception: Error {
        case UnknownHost
        case InvalidFile
        case InvalidHeader
    }
}

public extension AWS {
    
    struct S3 {
        
        public struct Bucket {
            public let name : String
            public let region : Region
            
            public init(name: String, region: Region) {
                self.name = name
                self.region = region
            }
            
            var host : String {
                return "\(name).\(region.rawValue)"
            }
        }
        
        public enum Region : String {
            case usEast1        = "s3.amazonaws.com"
            case usEast2        = "s3.us-east-2.amazonaws.com"
            case usWest1        = "s3-us-west-1.amazonaws.com"
            case usWest2        = "s3-us-west-2.amazonaws.com"
            
            case ueWest1        = "s3-eu-west-1.amazonaws.com"
            case ueCentral1     = "s3.eu-central-1.amazonaws.com"
            
            case apSouth1       = "s3.ap-south-1.amazonaws.com"
            case apSoutheast1   = "s3-ap-southeast-1.amazonaws.com"
            case apSoutheast2   = "s3-ap-southeast-2.amazonaws.com"
            case apNortheast1   = "s3-ap-northeast-1.amazonaws.com"
            case apNortheast2   = "s3.ap-northeast-2.amazonaws.com"
            case saEast1        = "s3-sa-east-1.amazonaws.com"
        }
        
        private static func prepare(_ access: AWS.Access, method: String, bucket: Bucket, path: String, contentType: String, customHeaders: [(String,String)] = []) throws -> (CURL, UnsafeMutablePointer<curl_slist>) {
            
            let _heads = customHeaders.sorted { (h1, h2) -> Bool in
                return h1.0.compare(h2.0) == .orderedAscending
            }
            
            let _path = path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            let host = bucket.host
            access.update()
            let resource = "/\(bucket.name)/\(_path)"
            
            var stringToSign = "\(method)\n\n\(contentType)\n\(access.timestamp)"
            for h in _heads {
                stringToSign += "\n\(h.0.lowercased()):\(h.1)"
            }
            stringToSign += "\n\(resource)"
            let signature = access.signV4(stringToSign)
            let url = "https://\(host)/\(_path)"
            let curl = CURL(url: url)
            
            if AWS.debug {
                _ = curl.setOption(CURLOPT_VERBOSE, int: 1)
                _ = curl.setOption(CURLOPT_STDERR, v: stdout)
            }
            
            var headers: UnsafeMutablePointer<curl_slist>? = nil
            headers = curl_slist_append(headers, "Host: \(host)")
            headers = curl_slist_append(headers, "Date: \(access.timestamp)")
            headers = curl_slist_append(headers, "Content-Type: \(contentType)")
            headers = curl_slist_append(headers, "Authorization: AWS \(access.key):\(signature)")
            for h in customHeaders {
                headers = curl_slist_append(headers, "\(h.0): \(h.1)")
            }
            
            _ = curl.setOption(CURLOPT_FOLLOWLOCATION, int: 1)
            guard let list = headers else {
                throw AWS.Exception.InvalidHeader
            }
            _ = curl.setOption(CURLOPT_HTTPHEADER, v: list)
            return (curl, list)
        }
        
        public static func deleteObject(named name: String, ofType contentType: String, from bucket: Bucket, access: AWS.Access) throws {
            
            let (curl, headers) = try prepare(access, method: "DELETE", bucket: bucket, path: name, contentType: contentType)
            
            _ = curl.setOption(CURLOPT_CUSTOMREQUEST, s: "DELETE")
            let (code, _, _) = curl.performFully()
            guard code == 0 else {
                throw AWS.Exception.InvalidFile
            }
            curl_slist_free_all(headers)
        }
        
        public static func downloadObject(named name: String, ofType contentType: String, from bucket: Bucket, access: AWS.Access) throws -> [UInt8] {
            
            let (curl, headers) = try prepare(access, method: "GET", bucket: bucket, path: name,  contentType: contentType)
            
            _ = curl.setOption(CURLOPT_HTTPGET, int: 1)
            
            let (code, _, body) = curl.performFully()
            guard code == 0 else {
                throw AWS.Exception.InvalidFile
            }
            curl_slist_free_all(headers)
            return body
        }
        
        
        public enum ACL {
            
            case `default`
            case publicRead
            
            var headerValue : String? {
                switch self {
                case .default: return nil
                case .publicRead: return "public-read"
                }
            }
        }
        
        
        
        public static func uploadObject(at fileURL: URL, ofType contentType: String, withName name: String, to bucket: Bucket, acl: ACL, access: AWS.Access) throws {
            
            var fileInfo = stat()
            stat(fileURL.path, &fileInfo)
            
            guard fileInfo.st_size > 0,
                let fpointer = fopen(fileURL.path, "rb") else {
                    throw AWS.Exception.InvalidFile
            }
            
            var _headers = [(String,String)]()
            if let _acl = acl.headerValue {
                _headers.append(("x-amz-acl", _acl))
            }
            
            let (curl, headers) = try prepare(access, method: "PUT", bucket: bucket, path: name, contentType: contentType, customHeaders: _headers)
            
            _ = curl.setOption(CURLOPT_INFILESIZE_LARGE, int:
                fileInfo.st_size)
            _ = curl.setOption(CURLOPT_READDATA, v: fpointer)
            _ = curl.setOption(CURLOPT_UPLOAD, int: 1)
            _ = curl.setOption(CURLOPT_PUT, int: 1)
            _ = curl.setOption(CURLOPT_READFUNCTION, f: { ptr, size, nitems, stream in
                if let fstream = stream {
                    let f = fstream.assumingMemoryBound(to: FILE.self)
                    return fread(ptr, size, nitems, f)
                } else {
                    return 0
                }
            })
            
            let (code, _, bodyBytes) = curl.performFully()
            guard code == 0 else {
                throw AWS.Exception.InvalidFile
            }
            curl_slist_free_all(headers)
            
        }
    }
    
}

