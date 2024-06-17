//
//  SidebarView.swift
//  MacOSBinAnalyzerGUI
//
//  Created by Tristán on 18/3/24.
//

import SwiftUI

struct SidebarView: View {
    @Binding var userCreatedGroups: [QueryGroup]
    @Binding var selection: QuerySection // to know what tab has been selected
    
    var body: some View {
        List(selection: $selection) {
            Section("Configuration"){
                Label(QuerySection.path.displayName, systemImage: QuerySection.path.iconName).tag(QuerySection.path)
            }
            
            Section("Favorites") {
                ForEach(QuerySection.allCases) { selection in
                    Label(selection.displayName, systemImage: selection.iconName).tag(selection) // display sidebar options
                }
            }
            
            Section("Your Queries") {
                ForEach($userCreatedGroups) { $group in
                    HStack {
                        Image(systemName: "folder")
                        TextField("New Group", text: $group.title)
                    }.tag(QuerySection.list(group)) // display sidebar options
                }
            }
        }
        
        // button to add query groups (out of the list so its always visible)
        .safeAreaInset(edge: .bottom){
            Button(action: {
                let newGroup = QueryGroup(title: "New Group")
                userCreatedGroups.append(newGroup)
            }, label: {
                Label("Create Query Group", systemImage: "plus.circle")
            }).buttonStyle(.borderless).foregroundColor(.accentColor).padding().frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
