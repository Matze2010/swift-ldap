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

    func testInitialization() throws {
    
        XCTAssertNoThrow(try SwiftLDAP(url: credentials.testURL))
        
    }
}

