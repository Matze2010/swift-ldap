//
//  SwiftLDAP.swift
//  
//
//  Created by Mathias Gisch on 28.08.21.
//

import Foundation
import OpenLDAP

struct SwiftLDAP {
    
    /// LDAP handler pointer
    internal var ldap: OpaquePointer? = nil
    
    /// LDAP-Server URL
    internal let url: String
    
    init(url: String) throws {
        self.url = url
        
        ldap = OpaquePointer(bitPattern: 0)
        var r = ldap_initialize(&ldap, url)
        
        guard r == 0 else {
          throw Exception.message(SwiftLDAP.error(r))
        }
    }
    
    init(host: String, port: Int = 389, secure: Bool = false) throws {
        try self.init(url: "ldap\(secure ? "s" : "")://\(host):\(port)")
    }
    
}


extension SwiftLDAP {
    
    public enum Exception: Error {
      case message(String)
    }
    
    public static func error(_ errno: Int32) -> String {
      return String(cString: ldap_err2string(errno))
    }
    
}
