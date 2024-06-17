//
//  QueryListView.swift
//  MacOSBinAnalyzerGUI
//
//  Created by Tristán on 18/3/24.
//
// View of a created query list

import SwiftUI

struct QueryListView: View {
    let title: String
    @Binding var queries: [Query]
    @Binding var selectedQuery: Query
    @State private var inspectorIsShown: Bool = false
    @Binding var databasePath: String
    @State private var newQuery = ""
    @State private var updateSuccessMessage = ""

    var body: some View {
        VStack {
            List {
                ForEach($queries) { $query in
                    QueryView(query: $query, selectedQuery: $selectedQuery, inspectorIsShown: $inspectorIsShown, databasePath: $databasePath)
                }
            }
            .listStyle(SidebarListStyle()) // Apply sidebar list style
            
            Divider() // Add divider between list and toolbar
            
            HStack {
                Spacer() // Push buttons to the right
                
                Button(action: {
                    let newQuery = Query(title: "New Query")
                    queries.append(newQuery)
                }) {
                    Label("Create New Query", systemImage: "plus")
                }
                .buttonStyle(FilledButtonStyle())

                Button(action: {
                    inspectorIsShown.toggle()
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

                Divider()

                Button("Save") {
                    if let index = queries.firstIndex(where: { $0.id == selectedQuery.id }) {
                        queries[index].query = newQuery
                        updateSuccessMessage = "Query updated successfully"
                    }
                }
                .buttonStyle(FilledButtonStyle())
                .padding(.vertical, 12)

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

struct FilledButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundColor(.white)
            .padding(.vertical, 12)
            .padding(.horizontal, 24)
            .background(configuration.isPressed ? Color.blue.opacity(0.8) : Color.blue)
            .cornerRadius(8)
    }
}

