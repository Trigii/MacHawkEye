//
//  PrebuildQueryListView.swift
//  MacOSBinAnalyzerGUI
//
//  Created by Tristán on 20/3/24.
//

import SwiftUI

struct PrebuildQueryListView: View {
    let title: String
    @Binding var selectedQuery: Query
    @State private var inspectorIsShown: Bool = false
    @Binding var databasePath: String
    @State private var isExpanded: [Bool]

    init(title: String, selectedQuery: Binding<Query>, databasePath: Binding<String>) {
        self.title = title
        self._selectedQuery = selectedQuery
        self._databasePath = databasePath
        _isExpanded = State(initialValue: Array(repeating: false, count: prebuildQueries.count))
    }

    var body: some View {
        ScrollView {
            ForEach(prebuildQueries.indices, id: \.self) { index in
                let category = prebuildQueries[index]

                DisclosureGroup(isExpanded: $isExpanded[index]) {
                    ForEach(category.queries) { query in
                        QueryView(query: .constant(query), selectedQuery: $selectedQuery, inspectorIsShown: $inspectorIsShown, databasePath: $databasePath)
                    }
                    .padding(.leading, 10) // Add some indentation
                } label: {
                    Text(category.title)
                        .font(.headline)
                        .foregroundColor(Color.blue)
                }
                .padding(.vertical, 8)
                .padding(.horizontal, 16)
                .background(RoundedRectangle(cornerRadius: 8).foregroundColor(Color.secondary.opacity(0.2)))
                .padding(.vertical, 4)
                .padding(.horizontal, 8)
            }
            .padding(.vertical, 8)
        }
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

    let prebuildQueries: [PrebuiltQueryCategory] = [
        PrebuiltQueryCategory(title: "Privileged Binaries", queries: [
            Query(title: "High privileged binaries", isPreBuilt: true, query: "SELECT path, privileged, privilegedReasons FROM executables WHERE privileged='High';", description: "Get executables with high privileges"),
            Query(title: "Medium privileged binaries", isPreBuilt: true, query: "SELECT path, privileged, privilegedReasons FROM executables WHERE privileged='Medium';", description: "Get executables with medium privileges")
        ]),
        PrebuiltQueryCategory(title: "Injectable privileged binaries", queries: [
            Query(title: "High privileged and injectable (medium or high) binaries", isPreBuilt: true, query: "SELECT path, privileged, privilegedReasons, injectable, injectableReasons FROM executables WHERE privileged='High' AND (injectable == 'Medium' OR injectable == 'High');", description: "Get executables with high privileges and injectable level medium or high"),
            Query(title: "Medium privileged and injectable (high) binaries", isPreBuilt: true, query: "SELECT path, privileged, privilegedReasons, injectable, injectableReasons FROM executables WHERE privileged='Medium' AND injectable == 'High';", description: "Get executables with medium privileges and injectable level high")
        ]),
        PrebuiltQueryCategory(title: "Specific Injection queries", queries: [
            Query(title: "Electron code injection techniques", isPreBuilt: true, query: "SELECT path, privileged, privilegedReasons, injectable, injectableReasons FROM executables WHERE injectableReasons LIKE '%isElectron%';", description: "Use Electron code injection techniques to inject code into the app"),
            Query(title: "Electron app bundles", isPreBuilt: true, query: "SELECT bundle_path FROM bundles WHERE isElectron;", description: "Get Electron app bundles"),
            Query(title: "Get DYLD_INSERT_LIBRARIES without library validation", isPreBuilt: true, query: "SELECT e.path, e.privileged, e.privilegedReasons FROM executables e WHERE e.noLibVal = 1 AND e.allowDyldEnv = 1;", description: "Use the env variable DYLD_INSERT_LIBRARIES to load arbitrary libraries into the binary"),
            Query(title: "Binaries with the entitlement com.apple.system-task-ports", isPreBuilt: true, query: "SELECT path FROM executables where entitlements like '%com.apple.system-task-ports%';", description: "Get binaries with the entitlement com.apple.system-task-ports to read/write memory of other processes"),
            Query(title: "Binaries with the entitlement com.apple.security.get-task-allow", isPreBuilt: true, query: "SELECT path FROM executables where entitlements like '%com.apple.security.get-task-allow%';", description: "Get binaries with the entitlement com.apple.security.get-task-allow that allows other processes to get the task port of the binary"),
            Query(title: "Hijackable (Dyld hijack & Dlopen hijack) binaries", isPreBuilt: true, query: "SELECT e.path, e.privileged, e.privilegedReasons, l.path FROM executables e JOIN executable_libraries el ON e.path = el.executable_path JOIN libraries l ON el.library_path = l.path WHERE l.isHijackable = 1 AND e.noLibVal = 1;", description: "Perform a Dyld hijack on the binary by creating/overwritting the library. These are potentially unexploitable unless you can modify apps (kTCCServiceSystemPolicyAppBundles)"),
            Query(title: "Other potential Dlopen hijackable binaries", isPreBuilt: true, query: "SELECT e.path, e.privileged, e.privilegedReasons, l.path FROM executables e JOIN executable_libraries el ON e.path = el.executable_path JOIN libraries l ON el.library_path = l.path WHERE l.isDyld = 0 AND l.pathExists = 0 AND l.isHijackable = 0 AND e.noLibVal = 1;", description: "Perform a Dlopen hijack on the binary by creating/overwritting the library in the DLopen searched place. These are potentially unexploitable unless you can modify apps (kTCCServiceSystemPolicyAppBundles)"),
            Query(title: "Non apple apps with high/medium privileges, no library validation, and relative imports", isPreBuilt: true, query: "SELECT e.path, e.privileged, e.privilegedReasons, l.path FROM executables e JOIN executable_libraries el ON e.path = el.executable_path JOIN libraries l ON el.library_path = l.path WHERE e.noLibVal=1 AND (e.privileged='High' OR e.privileged='Medium') AND NOT e.isAppleBin AND l.isRelative AND NOT e.privilegedReasons='isDaemon';", description: "Check non apple apps with high/medium privileges, no library validation, and with relative imports to abuse them. Move the application to a writable folder and hijack the relative library")
        ]),
        PrebuiltQueryCategory(title: "Executable Queries", queries: [
            Query(title: "Unrestricted executables and no restricted segments", isPreBuilt: true, query: "SELECT path FROM executables where isRestricted=0;", description: "Unrestricted executables (no hardeneded runtime, lib validation or restrction flag) and no restricted segments (no __RESTRICT/__restrict)"),
            Query(title: "Unrestricted non Apple executables", isPreBuilt: true, query: "SELECT path FROM executables where isRestricted=0 and isAppleBin=0;", description: "Unrestricted non Apple executables"),
            Query(title: "Executables with sandbox exceptions", isPreBuilt: true, query: "SELECT path FROM executables WHERE sandboxDefinition != '';", description: "Executables with sandbox exceptions"),
            Query(title: "Executables with ACLs", isPreBuilt: true, query: "SELECT path FROM executables WHERE acls != '';", description: "Executables with ACLs"),
            Query(title: "Executables with XPC rules", isPreBuilt: true, query: "SELECT path, xpcRules FROM executables WHERE xpcRules != '{}';", description: "Executables with XPC rules"),
            Query(title: "Executables with TCC perms", isPreBuilt: true, query: "SELECT path, tccPerms FROM executables WHERE tccPerms != '';", description: "Executables with TCC perms"),
            Query(title: "Executables with macServices", isPreBuilt: true, query: "SELECT path, machServices FROM executables WHERE machServices != '';", description: "Executables with macServices")
        ]),
        PrebuiltQueryCategory(title: "Bundles Queries", queries: [
            Query(title: "Bundles with exposed schemes", isPreBuilt: true, query: "SELECT bundle_path, schemes FROM bundles WHERE schemes != '';", description: "Bundles with exposed schemes"),
            Query(title: "Bundles with exposed utis", isPreBuilt: true, query: "SELECT bundle_path, utis FROM bundles WHERE utis != '';", description: "Bundles with exposed utis")
        ])
    ]
}

// Struct to hold prebuilt query categories
struct PrebuiltQueryCategory: Identifiable {
    let id = UUID()
    let title: String
    let queries: [Query]
}
