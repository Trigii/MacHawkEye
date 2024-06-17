//
//  AllQueryListView.swift
//  MacOSBinAnalyzerGUI
//
//  Created by Tristán on 20/3/24.
//

import SwiftUI

struct AllQueryListView: View {
    let title: String
    @Binding var queryGroups: [QueryGroup]
    @Binding var selectedQuery: Query
    @Binding var databasePath: String
    @State private var newQuery = ""
    @State private var updateSuccessMessage = ""
    @State private var inspectorIsShown: Bool = false
    
    var body: some View {
        VStack {
            List {
                ForEach(queryGroups) { group in
                    Section(header: Text(group.title)) {
                        ForEach(group.queries) { query in
                            QueryView(query: .constant(query), selectedQuery: $selectedQuery, inspectorIsShown: $inspectorIsShown, databasePath: $databasePath)
                        }
                    }
                }
            }
            .listStyle(SidebarListStyle()) // Apply sidebar list style
            
            Divider() // Add divider between list and toolbar
            
            HStack {
                Spacer() // Push buttons to the right
                
                Button(action: {
                    inspectorIsShown.toggle() // Toggle inspector
                }) {
                    Label("Show Inspector", systemImage: "sidebar.right")
                }
                .buttonStyle(FilledButtonStyle())
            }
            .padding()
        }
        .navigationTitle(title)
        .inspector(isPresented: $inspectorIsShown) {
            VStack(alignment: .leading, spacing: 16) {
                Text(selectedQuery.title)
                    .font(.title)
                    .foregroundColor(Color.blue)
                    .padding(.bottom, 8)
                
                Text("Database Path:")
                    .font(.headline)
                    .foregroundColor(Color.gray)
                
                Text(databasePath)
                    .font(.body)
                    .foregroundColor(Color.white)
                    .padding(.bottom, 8)
                
                Text("Is Prebuilt:")
                    .font(.headline)
                    .foregroundColor(Color.gray)
                
                Text(selectedQuery.isPreBuilt ? "Yes" : "No")
                    .font(.body)
                    .foregroundColor(Color.white)
                    .padding(.bottom, 8)
                
                Divider()
                
                Text("Current Query:")
                    .font(.headline)
                    .foregroundColor(Color.gray)
                
                Text(selectedQuery.query ?? "N/A")
                    .font(.body)
                    .foregroundColor(Color.white)
                    .padding(.bottom, 8)
                
                Divider()
                
                Text("Edit Query:")
                    .font(.headline)
                    .foregroundColor(Color.gray)
                
                TextField(selectedQuery.query ?? "Enter Query", text: $newQuery)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding()
                    .frame(maxWidth: .infinity)
                    .onAppear {
                        // Pre-populate the text field with the previously set query
                        newQuery = selectedQuery.query ?? ""
                    }
                
                Divider()
                
                Button("Save") {
                    // Update the query's query property
                    if let groupIndex = queryGroups.firstIndex(where: { $0.queries.contains(where: { $0.id == selectedQuery.id }) }) {
                        if let queryIndex = queryGroups[groupIndex].queries.firstIndex(where: { $0.id == selectedQuery.id }) {
                            queryGroups[groupIndex].queries[queryIndex].query = newQuery
                            updateSuccessMessage = "Query updated successfully" // Set success message
                        }
                    }
                }
                .buttonStyle(FilledButtonStyle())
                .padding(.vertical, 12)
                
                // Display success message if available
                if !updateSuccessMessage.isEmpty {
                    Text(updateSuccessMessage)
                        .foregroundColor(.green)
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
