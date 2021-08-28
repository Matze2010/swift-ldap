//
//  LDAPNIOTest.swift
//  
//
//  Created by Mathias Gisch on 28.08.21.
//

@testable import SwiftLDAP
import Foundation
import XCTest
import NIO


final class LDAPNIOTests: XCTestCase {
    
    static let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 2)
    static let credentials = TestCredentials()
    
    func testBinding() throws {
        let ldap = try SwiftLDAP(url: Self.credentials.testURL)
        let auth = SwiftLDAP.AuthMechanism.simple(dn: Self.credentials.testBDN, password: Self.credentials.testPWD)
        
        let _ = ldap.bind(auth: auth, on: Self.eventLoopGroup.next()).whenFailure { error in
            XCTFail(error.localizedDescription)
        }
    }
    
    func testSearch() throws {
        let ldap = try SwiftLDAP(url: Self.credentials.testURL)
        let auth = SwiftLDAP.AuthMechanism.simple(dn: Self.credentials.testBDN, password: Self.credentials.testPWD)
        let eventLoop = Self.eventLoopGroup.next()
        
        let searchFuture: EventLoopFuture<[Message]?> = ldap.bind(auth: auth, on: eventLoop).flatMap {
            var searchParam = SwiftLDAP.SearchParameter.empty
            searchParam.base = LDAPNIOTests.credentials.testBASEDN
            return ldap.search(for: searchParam, on: eventLoop)
        }
        searchFuture.whenFailure { error in
            XCTFail(error.localizedDescription)
        }
    }
    
}
