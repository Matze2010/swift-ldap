//
//  Messages.swift
//  
//
//  Created by Mathias Gisch on 28.08.21.
//

import Foundation
import OpenLDAP

struct ResultSet {
    internal var _result: [Result] = .init()
    internal var _attributes: [Attributes] = .init()
    internal var _references: [Reference] = .init()
    
    mutating public func append(_ result: Result?) {
        if let entry = result {
            _result.append(entry)
        }
    }
    
    mutating public func append(_ result: Attributes?) {
        if let entry = result {
            _attributes.append(entry)
        }
    }
    
    mutating public func append(_ result: Reference?) {
        if let entry = result {
            _references.append(entry)
        }
    }
    
}

struct Result {
    
    /// error code of result
    internal var _errCode = Int32(0)

    /// error code of result, read only
    public var errCode: Int { Int(_errCode) }

    /// error message
    internal var _errMsg = ""

    /// error message, read only
    public var errMsg: String { _errMsg }

    /// matched dn
    internal var _matched = ""

    /// matched dn, read only
    public var matched: String { _matched }

    /// referrals as an array of string
    internal var _ref = [String]()

    /// referrals as an array of string, read only
    public var referrals: [String] { _ref }
    
    init?(message: OpaquePointer, ldap: SwiftLDAP) {
        
        var emsg = UnsafeMutablePointer<Int8>(bitPattern: 0)
        var data = UnsafeMutablePointer<Int8>(bitPattern: 0)
        var ref = UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>(bitPattern: 0)
        
        let res_parse = ldap_parse_result(ldap.ldap, message, &_errCode, &data, &emsg, &ref, nil, 0)
        guard res_parse == LDAP_SUCCESS else {
          return nil
        }

        if data != nil {
          _matched = String(pstr: data!)
          ldap_memfree(data)
        }
        
        if emsg != nil {
          _errMsg = String(pstr: emsg!)
          ldap_memfree(emsg)
        }
        
        var rf = ref
        while(rf != nil) {
          guard let p = rf?.pointee else {
            break
          }
          _ref.append(String(pstr: p))
          ldap_memfree(p)
          rf = rf?.successor()
        }
        
        if ref != nil {
          ldap_memfree(ref)
        }
    }
}

struct Attribute {
    let key: String
    let values: [String]
}

struct Attributes {
    
    /// name of the attribute
    internal var _name = ""

    /// name of the attribute, read only
    public var name: String { _name }

    /// attribute value set array
    internal var _attributes: [Attribute] = .init()

    /// attribute value set array, read only
    public var attributes: [Attribute] { _attributes }
    
    init?(message entry: OpaquePointer, ldap: SwiftLDAP) {
        
        guard let pName = ldap_get_dn(ldap.ldap, entry) else {
          return
        }
        
        _name = String(pstr: pName)
        ldap_memfree(pName)
        
        var ber = OpaquePointer(bitPattern: 0)
        var a = ldap_first_attribute(ldap.ldap, entry, &ber)
        
        while(a != nil) {
            
            var values: [String] = .init()
            let key = String(cString: a!)
            let valueSet = ldap_get_values_len(ldap.ldap, entry, a!)
            var cursor = valueSet
            
            while(cursor != nil) {
              guard let pBer = cursor?.pointee else {
                break
              }//end guard
              let b = pBer.pointee
                
              values.append(String(ber: b))
                
              cursor = cursor?.successor()
            }
            
            let newAttribute = Attribute(key: key, values: values)
            _attributes.append(newAttribute)
            
            if valueSet != nil {
              ldap_value_free_len(valueSet)
            }
            
            //_attributes.append(Attribute(ldap: ldap, entry: entry, tag: a!))
            ldap_memfree(a)
            a = ldap_next_attribute(ldap.ldap, entry, ber)
        }
        
        ber_free(ber, 0)
    }
}

struct Reference {
    
    /// value set in an array of string
    internal var _values = [String] ()

    /// value set in an array of string, read only
    public var values: [String] { _values }
    
    init?(message reference: OpaquePointer, ldap: SwiftLDAP) {
        
        var referrals = UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>(bitPattern: 0)

        // *NOTE* ldap_value_free is deprecated so have to use memfree in chain instead
        let res_parse = ldap_parse_reference(ldap.ldap, reference, &referrals, nil, 0)
        guard res_parse == LDAP_SUCCESS else {
          return
        }
        
        var cursor = referrals
        while(cursor != nil) {
          guard let pstr = cursor?.pointee else {
            break
          }
            
          _values.append(String(pstr: pstr))
          ldap_memfree(pstr)
          cursor = cursor?.successor()
        }
        
        ldap_memfree(referrals)
    }
}
