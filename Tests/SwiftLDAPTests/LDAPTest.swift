//
//  File.swift
//  
//
//  Created by Mathias Gisch on 28.08.21.
//

@testable import SwiftLDAP
import Foundation
import XCTest


final class LDAPTests: XCTestCase {
    
    let credentials = TestCredentials()

    func testInitializationAndBinding() throws {
    
        var ldap: SwiftLDAP?
        XCTAssertNoThrow(ldap = try SwiftLDAP(url: credentials.testURL))
        XCTAssertNotNil(ldap)
        
        let auth = SwiftLDAP.AuthMechanism.simple(dn: credentials.testBDN, password: credentials.testPWD)
        XCTAssertNoThrow(try ldap?.bind(auth: auth))
    }
    
    func testSearch() throws {
        let ldap = try SwiftLDAP(url: credentials.testURL)
            
        let auth = SwiftLDAP.AuthMechanism.simple(dn: credentials.testBDN, password: credentials.testPWD)
        try ldap.bind(auth: auth)
        
        var searchParam = SwiftLDAP.SearchParameter.empty
        searchParam.base = credentials.testBASEDN
        searchParam.scope = .children
        
        XCTAssertNoThrow(try ldap.search(for: searchParam))
    }
}

