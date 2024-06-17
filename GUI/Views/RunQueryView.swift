//
//  RunQueryView.swift
//  MacOSBinAnalyzerGUI
//
//  Created by Tristán on 19/3/24.
//

import SwiftUI

struct RunQueryView: View {
    @Binding var query: Query
    @Binding var databasePath: String
    @State private var searchTerm: String = ""
    
    var body: some View {
        if let queryResults = SQLiteManager.executeQuery(query.query, databasePath: databasePath) {
            if !queryResults.isEmpty {
                VStack {
                    // Column names at the top
                    QueryColumnHeaderView(row: queryResults.first!)
                    
                    // Values below the column names
                    ScrollView {
                        LazyVStack {
                            ForEach(queryResults.filter {
                                searchTerm.isEmpty || $0.values.joined(separator: " ").localizedCaseInsensitiveContains(searchTerm)
                            }, id: \.self) { row in
                                QueryResultRowView(row: row)
                            }
                        }
                    }.searchable(text: $searchTerm)
                }
                .padding()
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

struct QueryColumnHeaderView: View {
    var row: [String: String]
    
    var body: some View {
        HStack {
            Spacer() // Aligns path column header to the center
            ForEach(row.sorted(by: <), id: \.key) { (key, _) in
                Spacer()
                Text(key)
                    .fontWeight(.bold)
                    .foregroundColor(.blue)
                    .padding(.horizontal)
                    .frame(maxWidth: .infinity, alignment: .center)
                Spacer() // Aligns other column headers to the center
            }
        }
        .padding(.vertical, 8)
        .background(Color.secondary.opacity(0.2))
    }
}


struct QueryResultRowView: View {
    var row: [String: String]
    
    var body: some View {
        HStack {
            ForEach(row.sorted(by: <), id: \.key) { (key, value) in
                Spacer()
                Text(value)
                    .foregroundColor(.primary)
                    .padding(.horizontal)
                    .frame(maxWidth: .infinity, alignment: .center) // Aligning center
                Spacer()
            }
        }
        .padding(.vertical, 8)
        .background(Color.secondary.opacity(0.1))
    }
}
