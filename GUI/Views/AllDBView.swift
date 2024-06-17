//
//  AllDBView.swift
//  MacOSBinAnalyzerGUI
//
//  Created by Tristán on 31/3/24.
//

import SwiftUI

struct AllDBView: View {
    let title: String
    @Binding var selectedQuery: Query
    @State private var inspectorIsShown: Bool = false
    @Binding var databasePath: String

    var body: some View {
        List {
            ForEach(allDBQueries) { query in
                QueryView(query: .constant(query), selectedQuery: $selectedQuery, inspectorIsShown: $inspectorIsShown, databasePath: $databasePath)
            }
        }
        .listStyle(SidebarListStyle()) // Apply sidebar list style
        .navigationTitle(title)
        .toolbar {
            ToolbarItemGroup {
                Button {
                    inspectorIsShown.toggle()
                } label: {
                    Label("Show Inspector", systemImage: "sidebar.right")
                }
                .foregroundColor(.blue)
                .padding(.trailing) // Add some space between the button and the title
            }
        }
        .inspector(isPresented: $inspectorIsShown) {
            VStack(alignment: .leading, spacing: 16) {
                Text(selectedQuery.title)
                    .font(selectedQuery.title.count > 20 ? .title3 : .title)
                    .foregroundColor(Color.blue)
                    .padding(.bottom, 8)

                Text("Description")
                    .font(.headline)
                    .foregroundColor(Color.gray)
                
                Text(selectedQuery.description ?? "N/A")
                    .font(.body)
                    .foregroundColor(Color.white)
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

                Text("Query:")
                    .font(.headline)
                    .foregroundColor(Color.gray)
                
                if let query = selectedQuery.query {
                    Text(query)
                        .font(.body)
                        .foregroundColor(Color.white)
                        .padding(.bottom, 8)
                } else {
                    Text("N/A")
                        .font(.body)
                        .foregroundColor(Color.gray)
                        .padding(.bottom, 8)
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
    
    let allDBQueries: [Query] = [
        Query(title: "Get all Executables", isPreBuilt: false, query: "SELECT * FROM executables;", description: "Display all the Executables table"),
        Query(title: "Get all Libraries", isPreBuilt: false, query: "SELECT * FROM libraries;", description: "Display all the Libraries table"),
        Query(title: "Get all Bundles", isPreBuilt: false, query: "SELECT * FROM bundles;", description: "Display all the Bundles table"),
        Query(title: "Get all Scripts", isPreBuilt: false, query: "SELECT * FROM scripts;", description: "Display all the Scripts table")
    ]
}
