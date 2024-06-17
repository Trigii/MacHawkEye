//
//  ContentView.swift
//  MacOSBinAnalyzerGUI
//
//  Created by Tristán on 18/3/24.
//

import SwiftUI

struct ContentView: View {
    @State private var selection = QuerySection.all // sidebar selection state
    @State private var prebuiltQueries: [Query] = [] // TODO: change to prebuilt queries hardcoded
    @State private var userCreatedGroups: [QueryGroup] = []
    @State private var searchTerm: String = ""
    @Binding var databasePath: String
    @Binding var selectedQuery: Query
    
    var body: some View {
        NavigationSplitView {
            SidebarView(userCreatedGroups: $userCreatedGroups, selection: $selection) // we navigate through the sidebar
        } detail: { // depends on the selected tab
            if searchTerm.isEmpty {
                switch selection {
                case .path:
                    PathView(databasePath: $databasePath)
                case .all:
                    AllQueryListView(title: "All", queryGroups: $userCreatedGroups, selectedQuery: $selectedQuery, databasePath: $databasePath)
                case .prebuilt:
                    PrebuildQueryListView(title: "Prebuilt Queries", selectedQuery: $selectedQuery, databasePath: $databasePath)
                case .allDBInfo:
                    AllDBView(title: "All DB Content", selectedQuery: $selectedQuery, databasePath: $databasePath)
                case .list(let queryGroup):
                    // Create a binding for the queries in the selected query group
                    let groupQueries = $userCreatedGroups[getIndex(for: queryGroup)].queries
                    QueryListView(title: queryGroup.title, queries: groupQueries, selectedQuery: $selectedQuery, databasePath: $databasePath)
                }
            } else {
                let filteredQueries = userCreatedGroups.flatMap { $0.queries }.filter { $0.title.contains(searchTerm) }
                QueryListView(title: "Search Results", queries: .constant(filteredQueries), selectedQuery: $selectedQuery, databasePath: $databasePath)
                // Wrap filteredQueries in a constant Binding to satisfy the expected type
            }
        }
        .searchable(text: $searchTerm) // adds automatically the searchbar at the top
    }
    
    // Helper function to get the index of the selected query group
    private func getIndex(for queryGroup: QueryGroup) -> Int {
        if let index = userCreatedGroups.firstIndex(where: { $0.id == queryGroup.id }) {
            return index
        }
        return 0
    }
}

