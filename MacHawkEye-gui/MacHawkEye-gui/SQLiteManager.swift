//
//  SQLiteManager.swift
//  MacOSBinAnalyzerGUI
//
//  Created by Tristán on 19/3/24.
//
/*
import SQLite3

class SQLiteManager {
    static func executeQuery(_ query: String?, databasePath: String) -> [Result]? {
        guard let query = query else { return nil }
        var queryResults = [Result]()
        var columnIndex: Int = 0
        
        var db: OpaquePointer?
        if sqlite3_open(databasePath, &db) == SQLITE_OK {
            var stmt: OpaquePointer?
            if sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK {
                // Array to keep track of column names and their occurrences
                var columnNamesCount = [String: Int]()
                
                // Get column names and occurrences
                let columns = sqlite3_column_count(stmt)
                for i in 0..<columns {
                    if let columnName = sqlite3_column_name(stmt, i) {
                        let key = String(cString: columnName)
                        columnNamesCount[key, default: 0] += 1
                    }
                }
                
                while sqlite3_step(stmt) == SQLITE_ROW {
                    for i in 0..<columns {
                        if let columnName = sqlite3_column_name(stmt, i),
                            let columnValue = sqlite3_column_text(stmt, i) {
                            var key = String(cString: columnName)
                            
                            // If column name is not unique, append occurrence count
                            if let count = columnNamesCount[key], count > 1 {
                                let occurrenceIndex = key.lastIndex(of: ".") ?? key.endIndex
                                key.insert(contentsOf: "_\(columnIndex)", at: occurrenceIndex)
                                columnIndex += 1
                            }
                            
                            let value = String(cString: columnValue)
                            let result = Result(colName: key, colValue: value)
                            queryResults.append(result)
                        }
                    }
                    columnIndex = 0
                }
                sqlite3_finalize(stmt)
            } else {
                print("Error preparing statement")
            }
            sqlite3_close(db)
        } else {
            print("Error opening database")
        }
        return queryResults.isEmpty ? nil : queryResults
    }
}
*/
import SQLite3

class SQLiteManager {
    static func executeQuery(_ query: String?, databasePath: String) -> [[String: String]]? {
        guard let query = query else { return nil }
        var queryResults = [[String: String]]()
        var columnIndex: Int = 0
        
        var db: OpaquePointer?
        if sqlite3_open(databasePath, &db) == SQLITE_OK {
            var stmt: OpaquePointer?
            if sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK {
                // Array to keep track of column names and their occurrences
                var columnNamesCount = [String: Int]()
                
                // Get column names and occurrences
                let columns = sqlite3_column_count(stmt)
                for i in 0..<columns {
                    if let columnName = sqlite3_column_name(stmt, i) {
                        let key = String(cString: columnName)
                        columnNamesCount[key, default: 0] += 1
                    }
                }
                
                while sqlite3_step(stmt) == SQLITE_ROW {
                    var rowDict = [String: String]()
                    for i in 0..<columns {
                        if let columnName = sqlite3_column_name(stmt, i),
                            let columnValue = sqlite3_column_text(stmt, i) {
                            var key = String(cString: columnName)
                            
                            // If column name is not unique, append occurrence count
                            if let count = columnNamesCount[key], count > 1 {
                                let occurrenceIndex = key.lastIndex(of: ".") ?? key.endIndex
                                key.insert(contentsOf: "_\(columnIndex)", at: occurrenceIndex)
                                columnIndex += 1
                            }
                            
                            let value = String(cString: columnValue)
                            rowDict[key] = value
                        }
                    }
                    queryResults.append(rowDict)
                    columnIndex = 0
                }
                sqlite3_finalize(stmt)
            } else {
                print("Error preparing statement")
            }
            sqlite3_close(db)
        } else {
            print("Error opening database")
        }
        return queryResults.isEmpty ? nil : queryResults
    }
}
