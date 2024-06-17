//
//  QueryGroup.swift
//  MacOSBinAnalyzerGUI
//
//  Created by Tristán on 18/3/24.
//

import Foundation

struct QueryGroup: Identifiable, Hashable {
    let id = UUID()
    var title: String
    var queries: [Query]

    init(title: String, queries: [Query] = []) {
        self.title = title
        self.queries = queries
    }
}
