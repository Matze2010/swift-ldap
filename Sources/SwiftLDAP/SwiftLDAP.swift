//
//  SwiftLDAP.swift
//  
//
//  Created by Mathias Gisch on 28.08.21.
//

import Foundation
import OpenLDAP
import NIO

class SwiftLDAP {
    
    /// LDAP handler pointer
    internal var ldap: OpaquePointer? = nil
    
    /// LDAP-Server URL
    internal let url: String
    
    /// Queue for performing async
    internal let queue = DispatchQueue(label: "queue.swift-ldap")
    
    init(url: String) throws {
        self.url = url
        
        ldap = OpaquePointer(bitPattern: 0)
        let res_init = ldap_initialize(&ldap, url)
        
        guard res_init == LDAP_SUCCESS else {
          throw Exception.frameworkError(SwiftLDAP.error(res_init))
        }
        
        var proto = LDAP_VERSION3
        let _ = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &proto)
    }
    
    convenience init(host: String, port: Int = 389, secure: Bool = false) throws {
        try self.init(url: "ldap\(secure ? "s" : "")://\(host):\(port)")
    }
    
    deinit {
      ldap_unbind_ext_s(ldap, nil, nil)
    }
    
    public func bind(auth: AuthMechanism) throws {
        
        guard case .simple(let dn, let password) = auth else {
            throw SwiftLDAP.Exception.authenticationMechanismNotSupported
        }
        
        var cred = berval(bv_len: 0, bv_val: UnsafeMutablePointer<Int8>(bitPattern: 0))
        cred.bv_val = ber_strdup(password)
        cred.bv_len = ber_len_t(strlen(cred.bv_val))
        defer {
            ber_memfree(cred.bv_val)
        }
        
        let res_bind = ldap_sasl_bind_s(self.ldap, dn, nil, &cred, nil, nil, nil)
        guard res_bind == LDAP_SUCCESS else {
            throw Exception.frameworkError(SwiftLDAP.error(res_bind))
        }
    }
    
    public func bind(auth: AuthMechanism, on: EventLoop) -> EventLoopFuture<Void> {
        
        let promise: EventLoopPromise<Void> = on.makePromise()
        queue.async {
            do {
                try self.bind(auth: auth)
            } catch {
                promise.fail(error)
            }
            promise.succeed(())
        }
        
        return promise.futureResult
    }
    
    public func search(for search: SearchParameter) throws -> ResultSet? {
        
        var ldapControl = UnsafeMutablePointer<LDAPControl>(bitPattern: 0)
        var chain = OpaquePointer(bitPattern: 0)
        
        defer {
            ldap_control_free(ldapControl)
        }
        
        let res_search = withCArrayOfString(array: search.attributes) { pAttribute -> Int32 in

            // perform the search
            let result = ldap_search_ext_s(self.ldap, search.base, search.scope.rawValue, search.filter, pAttribute, 0, &ldapControl, nil, nil, 0, &chain)
            return result
        }
        guard res_search == LDAP_SUCCESS else {
            throw SwiftLDAP.Exception.frameworkError(SwiftLDAP.error(res_search))
        }
        
        guard let chain = chain else {
            return nil
        }

        defer {
            ldap_msgfree(chain)
        }
        
        var result = ResultSet()
        var msg = ldap_first_message(self.ldap, chain)
        while(msg != nil) {
          switch(UInt(ldap_msgtype(msg))) {
          case LDAP_RES_SEARCH_ENTRY:
            result.append(Attributes(message: msg!, ldap: self))
          case LDAP_RES_SEARCH_REFERENCE:
            result.append(Reference(message: msg!, ldap: self))
          case LDAP_RES_SEARCH_RESULT:
            result.append(Result(message: msg!, ldap: self))
          default:
            break
          }
          msg = ldap_next_message(ldap, msg)
        }
        
        return result
    }
    
    public func search(for search: SearchParameter, on: EventLoop) -> EventLoopFuture<ResultSet?> {
        
        let promise: EventLoopPromise<ResultSet?> = on.makePromise()
        queue.async {
            var searchResult: ResultSet? = nil
            do {
                searchResult = try self.search(for: search)
            } catch {
                promise.fail(error)
            }
            promise.succeed(searchResult)
        }
        
        return promise.futureResult
    }
}

extension SwiftLDAP {
    
    public typealias SearchAttribute = String
    
    public enum AuthMechanism {
        case simple(dn: String, password: String)
        case gssapi
        case spnego
        case digest
        case other
    }
    
    public enum SearchScope: ber_int_t {
        case base = 0
        case singlelevel = 1
        case subtree = 2
        case children = 3
        case `default` = -1
    }
    
    public struct SearchParameter {
        
        var base: String
        var filter: String
        var scope: SearchScope
        var attributes: [SearchAttribute]
        
        static var empty: SearchParameter {
            SearchParameter(base: "", filter: "(objectclass=*)", scope: .base, attributes: [])
        }
    }

}


extension SwiftLDAP {
    
    public enum Exception: Error {
        case frameworkError(String)
        case authenticationMechanismNotSupported
    }
    
    public static func error(_ errno: Int32) -> String {
      return String(cString: ldap_err2string(errno))
    }
}
