//
//  RunQueryAllView.swift
//  MacOSBinAnalyzerGUI
//
//  Created by Tristán on 31/3/24.
//

import SwiftUI

struct RunQueryAllView: View {
    @Binding var query: Query
    @Binding var databasePath: String
    @State private var searchText = ""
    
    var body: some View {
        if let queryResults = SQLiteManager.executeQuery(query.query, databasePath: databasePath) {
            if !queryResults.isEmpty {
                List {
                    ForEach(queryResults.filter { searchText.isEmpty ? true : $0.contains(where: { $0.value.localizedCaseInsensitiveContains(searchText) }) }, id: \.self) { row in
                        QueryResultsRowView(row: row)
                    }
                }
                .listStyle(PlainListStyle())
                .searchable(text: $searchText)
            } else {
                Text("No results found")
                    .foregroundColor(.red)
                    .padding()
            }
        } else {
            Text("Error executing query")
                .foregroundColor(.red)
                .padding()
        }
    }
}

struct QueryResultsRowView: View {
    var row: [String: String]
    
    var body: some View {
        VStack(alignment: .leading) {
            ForEach(row.sorted(by: <), id: \.key) { (key, value) in
                HStack {
                    Text(key)
                        .fontWeight(.bold)
                        .foregroundColor(.blue)
                    Text(value)
                        .foregroundColor(.primary)
                    Spacer()
                }
                .padding(.vertical, 4)
            }
        }
        .padding(.horizontal)
    }
}
