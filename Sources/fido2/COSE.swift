//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import Foundation

internal struct COSEKeyFieldType {
    static let kty: Int =  1
    static let alg: Int =  3
    static let crv: Int = -1
    static let xCoord: Int = -2
    static let yCoord: Int = -3
    static let n: Int = -1
    static let e: Int = -2
}

internal struct COSEKeyCurveType {
    static let p256: Int = 1
    static let p384: Int = 2
    static let p521: Int = 3
    static let x25519: Int = 4
    static let x448: Int = 5
    static let ed25519: Int = 6
    static let ed448: Int = 7
}

internal struct COSEKeyType {
    static let ec2: UInt8 = 2
    static let rsa: UInt8 = 3
}

internal protocol COSEKey {
    func toBytes() -> [UInt8]
}

internal struct COSEKeyEC2: COSEKey {
    var alg: Int
    var crv: Int
    var xCoord: [UInt8] // 32 bytes
    var yCoord: [UInt8] // 32 bytes

    var bytes: [UInt8] {
        get {
            var dic = [Int: Any]()
            dic.updateValue(Int64(COSEKeyType.ec2), forKey: COSEKeyFieldType.kty)
            dic.updateValue(Int64(self.alg), forKey: COSEKeyFieldType.alg)
            dic.updateValue(Int64(self.crv), forKey: COSEKeyFieldType.crv)
            dic.updateValue(self.xCoord, forKey: COSEKeyFieldType.xCoord)
            dic.updateValue(self.yCoord, forKey: COSEKeyFieldType.yCoord)
            
            return CBORWriter()
                .putIntKeyMap(dic)
                .getResult()
        }
    }
    
    func toBytes() -> [UInt8] {
        var dic = [Int: Any]()
        dic.updateValue(Int64(COSEKeyType.ec2), forKey: COSEKeyFieldType.kty)
        dic.updateValue(Int64(self.alg), forKey: COSEKeyFieldType.alg)
        dic.updateValue(Int64(self.crv), forKey: COSEKeyFieldType.crv)
        dic.updateValue(self.xCoord, forKey: COSEKeyFieldType.xCoord)
        dic.updateValue(self.yCoord, forKey: COSEKeyFieldType.yCoord)

        return CBORWriter()
            .putIntKeyMap(dic)
            .getResult()
    }
}
