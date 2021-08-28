//
//  Helpers.swift
//  
//
//  Created by Mathias Gisch on 28.08.21.
//

import Foundation
import OpenLDAP

extension String {
    init(ber: berval) {
        self = String(validatingUTF8: ber.bv_val) ?? ""
    }
    
    init(pstr: UnsafeMutablePointer<Int8>) {
      let ber = berval(bv_len: ber_len_t(strlen(pstr)), bv_val: pstr)
      self = String(ber: ber)
    }
}

public func withCArrayOfString<R>(array: [String] = [],
                                  _ body: (UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>?) throws -> R) rethrows -> R {

  if array.isEmpty {
    return try body(nil)
  }//end if

  // duplicate the array and append a null string
  var attr: [String?] = array
  attr.append(nil)

  // duplicate again and turn it into an array of pointers
  var parr = attr.map { $0 == nil ? nil : ber_strdup($0!) }
  defer {
        // release allocated string pointers.
        for p in parr { ber_memfree(UnsafeMutablePointer(mutating: p)) }
  }

  // perform the operation
  let r = try parr.withUnsafeMutableBufferPointer { try body ($0.baseAddress) }

  return r
}
