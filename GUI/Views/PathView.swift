//
//  PathView.swift
//  MacOSBinAnalyzerGUI
//
//  Created by Tristán on 19/3/24.
//

import SwiftUI

struct PathView: View {
    @Binding var databasePath: String
    @State private var newPath = ""
    @State private var updateSuccessMessage = "" // Message to indicate successful update
    
    var body: some View {
        VStack(spacing: 16) {
            Text("Database Path")
                .font(.headline)
                .foregroundColor(.primary)
            
            if databasePath != "" {
                TextField(databasePath, text: $newPath)
                    .frame(maxWidth: .infinity)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding(.horizontal)
            } else {
                TextField("Enter new path", text: $newPath)
                    .frame(maxWidth: .infinity)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding(.horizontal)
            }
            
            Button(action: {
                // Update the database path
                databasePath = newPath
                updateSuccessMessage = "Database path updated successfully" // Set success message
            }) {
                Text("Save")
                    .padding()
                    .foregroundColor(.white)
                    .background(Color.blue)
                    .cornerRadius(8)
            }
            .buttonStyle(BorderlessButtonStyle())
            
            if !updateSuccessMessage.isEmpty {
                Text(updateSuccessMessage)
                    .foregroundColor(.green)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .center)
    }
}

