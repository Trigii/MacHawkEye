//
//  QueryView.swift
//  MacOSBinAnalyzerGUI
//
//  Created by Tristán on 18/3/24.
//

import SwiftUI

struct QueryView: View {
    @Environment(\.openWindow) var openWindow
    
    @Binding var query: Query
    @Binding var selectedQuery: Query
    @Binding var inspectorIsShown: Bool
    @Binding var databasePath: String
    
    var body: some View {
        HStack {
            Image(systemName: "plus.magnifyingglass")
            TextField("New Query", text: $query.title).textFieldStyle(.plain)
            
            // query details button
            Button(action: {
                if inspectorIsShown && query.id == selectedQuery.id { // close the inspector if it's already opened
                    inspectorIsShown = false
                } else { // open inspector for the first time
                    inspectorIsShown = true // update the inspector state
                    selectedQuery = query // update the selected query state
                }
            }, label: {
                Text("Details")
            })
            
            // run query button
            Button(action: {
                selectedQuery = query // update the selected query state
                if let selectedQueryText = selectedQuery.query?.lowercased(), selectedQueryText.contains("select * from") {
                    openWindow(id: "run-query-all")
                } else {
                    openWindow(id: "run-query-default")
                }
            }, label: {
                Text("Run query")
            })
        }
    }
}

