//
//  MacOSBinAnalyzerGUIApp.swift
//  MacOSBinAnalyzerGUI
//
//  Created by Tristán on 18/3/24.
//

import SwiftUI

@main
struct MacOSBinAnalyzerGUI: App {
    @State private var databasePath: String = "" // Initial value for database path state
    @State private var selectedQuery: Query = Query(title: "") // Initial value for current query
    
    var body: some Scene {
        WindowGroup {
            ContentView(databasePath: $databasePath, selectedQuery: $selectedQuery)
                .frame(maxWidth: .infinity, maxHeight: .infinity) // Allow content view to expand
        }
        .windowStyle(HiddenTitleBarWindowStyle()) // Hide title bar for custom frame
        
        WindowGroup("Query Results", id: "run-query-default") {
            RunQueryView(query: $selectedQuery, databasePath: $databasePath)
                .frame(maxWidth: .infinity, maxHeight: .infinity) // Allow run query view to expand
        }
        .windowStyle(HiddenTitleBarWindowStyle()) // Hide title bar for custom frame
        
        WindowGroup("Query Results", id: "run-query-all") {
            RunQueryAllView(query: $selectedQuery, databasePath: $databasePath)
                .frame(maxWidth: .infinity, maxHeight: .infinity) // Allow run query view to expand
        }
        .windowStyle(HiddenTitleBarWindowStyle()) // Hide title bar for custom frame
    }
}

