//
//  Query.swift
//  MacOSBinAnalyzerGUI
//
//  Created by Tristán on 18/3/24.
//

import Foundation

struct Query: Identifiable, Hashable {
    let id = UUID()
    var title: String
    var isPreBuilt: Bool
    var query: String?
    var description: String?

    init(title: String, isPreBuilt: Bool = false, query: String? = nil, description: String = "") {
        self.title = title
        self.isPreBuilt = isPreBuilt
        self.query = query
        self.description = description
    }
}
