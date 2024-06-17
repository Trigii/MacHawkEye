#import "SQLiteModule.h"

@implementation SQLiteModule {
    sqlite3 *database;
}

- (instancetype)initWithDatabasePath:(NSString *)path {
    self = [super init];
    if (self) {
        // Open the database at the provided path
        if (sqlite3_open([path UTF8String], &database) != SQLITE_OK) {
            NSLog(@"Failed to open database with error: %s", sqlite3_errmsg(database));
            sqlite3_close(database);  // Close the potentially opened database before returning nil.
            return nil;
        }

        // Create the tables
        [self createTables];
    }
    return self;
}

- (void)createTables {
    char *errMsg;
    
    const char *createExecutablesTableSQL =
    "CREATE TABLE IF NOT EXISTS executables ("
    "path TEXT PRIMARY KEY, "       // Path of the executable
    "Architectures TEXT, "          // Archs of the bin (arm64, amd64...)
    "ExecutableType TEXT, "         // macOS Binary, python script...
    "extension TEXT, "              // extension of the executable
    "xAttrs TEXT, "                 // xAttrs of the executable
    "isSGID INTEGER, "              // if SGID
    "isSUID INTEGER, "              // if SUID
    "acls TEXT, "                   // acls the executable has
    "identifier TEXT, "             // ID
    "isAppleBin INTEGER, "          // if belongs to apple (com.apple.*)
    "inSbxContainer INTEGER, "      // If Sandbox container folder exists
    "xpcRules TEXT, "               // If the executable has some xpcRules defined in the authorizationDB
    "teamid TEXT, "                 // TeamID of the executable
    "flags INTEGER, "               // Signed flags
    "flagsString TEXT, "            // Signed flags string
    "certificatesJson TEXT, "       // String of the cert used to sign
    "isRestricted INTEGER, "        // If it has a flag preventing lo load arbitrary libraries of a restrict section
    "entitlements TEXT, "           // JSON of the entitlements
    "tccPerms TEXT, "               // TCC permissions from the database
    "sandboxDefinition TEXT, "      // If any custom sandbox definition
    "isRunning INTEGER, "           // If it's running
    "machServices TEXT, "           // Supported mach services
    "cdhash TEXT, "                 // CDHash of the binary
    "TCcategory INTEGER, "          // Trust Cache category
    "inTC INTEGER, "                // If it's in Trust Cache
    "isDaemon INTEGER, "            // If it's a Daemon
        
    "noLibVal INTEGER, "            // com.apple.security.cs.disable-library-validation || com.apple.private.security.clear-library-validation || (!isRestricted)
    "allowDyldEnv INTEGER, "        // com.apple.security.cs.allow-dyld-environment-variables || (!isSGID && !isSUID && !isRestricted)
    
    "isDebugger INTEGER, "          // com.apple.security.cs.debugger
    "bypassSIP INTEGER, "           // com.apple.rootless.install.heritable || com.apple.rootless.install
    "isProcInjector INTEGER, "      // com.apple.system-task-ports || task_for_pid-allow
    "writeTCC INTEGER, "            // com.apple.private.tcc.manager || com.apple.rootless.storage.TCC || tcc: kTCCServiceSystemPolicySysAdminFiles || tcc: kTCCServiceEndpointSecurityClient
    "writeSSV INTEGER, "            // com.apple.private.apfs.revert-to-snapshot || com.apple.private.apfs.create-sealed-snapshot
    "isKextLoader INTEGER, "        // com.apple.private.security.kext-management
    "isFDA INTEGER, "               // TCC: kTCCServiceSystemPolicyAllFiles
    "modAutoTasks INTEGER, "        // TCC: kTCCServiceAppleEvents
    "canModifApps INTEGER, "        // TCC: kTCCServiceSystemPolicyAppBundles
    "canInstallApps INTEGER, "      // system.install.apple-software and system.install.apple-software.standar-user
    "iCloudAccs INTEGER, "          // com.apple.private.icloud-account-access
    
    "privileged TEXT, "             // High if: bypassSIP || isProcInjector || writeTCC || writeSSV || isFDA || isSGID || isSUID || isDaemon || isKextLoader || modAutoTasks
    "privilegedReasons TEXT, "      // Medium if: isDebugger || canModifApps || com.apple.private.tcc.allow || kTCCServiceAll
    
    "injectable TEXT, "             // High if: (noLibVal && allowDyldEnv) || (noLibVal && Hijackable-Lib) || Bundle-is-Electron
    "injectableReasons TEXT)";      // Medium if: noLibVal || allowDyldEnv || com.apple.security.get-task-allow || Hijackable-Lib
                                    
                                    
    
    if (sqlite3_exec(database, createExecutablesTableSQL, NULL, NULL, &errMsg) != SQLITE_OK) {
        NSLog(@"Failed to create executables table: %s", errMsg);
        sqlite3_free(errMsg);
    }
    
    const char *createLibrariesTableSQL =
    "CREATE TABLE IF NOT EXISTS libraries ("
    "path TEXT PRIMARY KEY, "       // Path to the library
    "executable_id INTEGER, "       // ID
    "pathExists INTEGER, "          // If the lib exists in the path
    "isWeak INTEGER, "              // If it's a Weak command
    "isDyld INTEGER, "              // If the Dylib exists (could be inside the shared cache)
    "isRelative integer, "          // If the path to the dylib is relative (uses @executable_path or @loader_path)
    "canCreate INTEGER, "           // If the user could create the file/folders
    "isWritable INTEGER, "          // If the lib file is writable
    "isHijackable INTEGER);";       // If the lib: isWritable || canCreate
    
    if (sqlite3_exec(database, createLibrariesTableSQL, NULL, NULL, &errMsg) != SQLITE_OK) {
        NSLog(@"Failed to create libraries table: %s", errMsg);
        sqlite3_free(errMsg);
    }
    
    const char *createExecutableLibrariesTableSQL =
    "CREATE TABLE IF NOT EXISTS executable_libraries ("
    "executable_path TEXT, "
    "library_path TEXT, "
    "PRIMARY KEY(executable_path, library_path), "
    "FOREIGN KEY(executable_path) REFERENCES executables(path) ON DELETE CASCADE, "
    "FOREIGN KEY(library_path) REFERENCES libraries(path) ON DELETE CASCADE);";
        
    if (sqlite3_exec(database, createExecutableLibrariesTableSQL, NULL, NULL, &errMsg) != SQLITE_OK) {
        NSLog(@"Failed to create executable_libraries table: %s", errMsg);
        sqlite3_free(errMsg);
    }
    
    const char *createBundlesTableSQL =
    "CREATE TABLE IF NOT EXISTS bundles ("
    "bundle_path TEXT PRIMARY KEY, "
    "isElectron INTEGER, "
    "schemes TEXT, "
    "utis TEXT);";                     // If it's an Electron bundle
        
    if (sqlite3_exec(database, createBundlesTableSQL, NULL, NULL, &errMsg) != SQLITE_OK) {
        NSLog(@"Failed to create bundle table: %s", errMsg);
        sqlite3_free(errMsg);
    }
    
    const char *createExecutableBundlesTableSQL =
    "CREATE TABLE IF NOT EXISTS executable_bundles ("
    "bundle_path TEXT, "
    "executable_path TEXT, "
    "PRIMARY KEY(executable_path, bundle_path), "
    "FOREIGN KEY(executable_path) REFERENCES executables(path) ON DELETE CASCADE, "
    "FOREIGN KEY(bundle_path) REFERENCES bundles(path) ON DELETE CASCADE);";
        
    if (sqlite3_exec(database, createExecutableBundlesTableSQL, NULL, NULL, &errMsg) != SQLITE_OK) {
        NSLog(@"Failed to create bundle table: %s", errMsg);
        sqlite3_free(errMsg);
    }
    
    const char *createScriptsTableSQL =
    "CREATE TABLE IF NOT EXISTS scripts ("
    "script_path TEXT PRIMARY KEY);";                     // If it's an Electron bundle
        
    if (sqlite3_exec(database, createScriptsTableSQL, NULL, NULL, &errMsg) != SQLITE_OK) {
        NSLog(@"Failed to create bundle table: %s", errMsg);
        sqlite3_free(errMsg);
    }
}

- (void)storeScriptInfo:(NSString*) script_path{
    const char *insertExecutableSQL = "INSERT INTO scripts "
    "(script_path) "
    "VALUES (?);";
    sqlite3_stmt *statement;
    
    if (sqlite3_prepare_v2(database, insertExecutableSQL, -1, &statement, NULL) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, [script_path UTF8String], -1, NULL);
        
        // After binding all values
        if (sqlite3_step(statement) != SQLITE_DONE) {
            const char *errorMsg = sqlite3_errmsg(database);
            if (strstr(errorMsg, "UNIQUE constraint failed") == NULL) {
                NSLog(@"Failed to insert data for executable: %s", errorMsg);
            }
        }
    }
    else{
        NSLog(@"DB prepare error: %s", sqlite3_errmsg(database));
    }
    
}


- (void)storeInfo:(NSDictionary *)info forExecutable:(NSString *)executable withAllUTIs:(NSDictionary *)allUTIs withAllSchemes:(NSDictionary *)allSchemes {
    @autoreleasepool {
        const char *insertExecutableSQL = "INSERT INTO executables "
        "(path, Architectures, ExecutableType, extension, xAttrs, isSGID, isSUID, acls, identifier, isAppleBin, inSbxContainer, xpcRules, teamid, flags, flagsString, certificatesJson, isRestricted, entitlements, tccPerms, sandboxDefinition, isRunning, machServices, cdhash, TCcategory, inTC, isDaemon)"
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
        sqlite3_stmt *statement;
        
        NSString *relativePath = executable;
        NSString *absolutePath = [relativePath stringByStandardizingPath];
        const char *absPath = [absolutePath UTF8String];
        
        if (sqlite3_prepare_v2(database, insertExecutableSQL, -1, &statement, NULL) == SQLITE_OK) {
            sqlite3_bind_text(statement, 1,  absPath, -1, NULL);
            sqlite3_bind_text(statement, 2,  [info[@"Architectures"] UTF8String], -1, NULL);
            sqlite3_bind_text(statement, 3,  [info[@"ExecutableType"] UTF8String], -1, NULL);
            sqlite3_bind_text(statement, 4,  [info[@"extension"] UTF8String], -1, NULL);
            sqlite3_bind_text(statement, 5,  [info[@"Extended attributes"] UTF8String], -1, NULL);
            sqlite3_bind_int (statement, 6,  [info[@"isSGID"] intValue]);
            sqlite3_bind_int (statement, 7,  [info[@"isSUID"] intValue]);
            sqlite3_bind_text(statement, 8,  [info[@"acls"] UTF8String], -1, NULL);
            sqlite3_bind_text(statement, 9,  [info[@"identifier"] UTF8String], -1, NULL);
            sqlite3_bind_int (statement, 10, [info[@"isAppleBin"] intValue]);
            sqlite3_bind_int (statement, 11, [info[@"inSbxContainer"] intValue]);
            sqlite3_bind_text(statement, 12, [info[@"xpcRules"] UTF8String], -1, NULL);
            sqlite3_bind_text(statement, 13, [info[@"teamid"] UTF8String], -1, NULL);
            sqlite3_bind_int (statement, 14, [info[@"flags"] intValue]);
            sqlite3_bind_text(statement, 15, [info[@"flagsStrings"] UTF8String], -1, NULL);
            sqlite3_bind_text(statement, 16, [info[@"certificateDetails"] UTF8String], -1, NULL);
            sqlite3_bind_int (statement, 17, [info[@"isRestricted"] intValue]);
            sqlite3_bind_text(statement, 18, [info[@"entitlements"] UTF8String], -1, NULL);
            sqlite3_bind_text(statement, 19, [info[@"tccPerms"] UTF8String], -1, NULL);
            sqlite3_bind_text(statement, 20, [info[@"sandboxDefinition"] UTF8String], -1, NULL);
            sqlite3_bind_int (statement, 21, [info[@"isRunning"] intValue]);
            sqlite3_bind_text(statement, 22, [info[@"machServices"] UTF8String], -1, NULL);
            sqlite3_bind_text(statement, 23, [info[@"cdhash"] UTF8String], -1, NULL);
            sqlite3_bind_int (statement, 24, [info[@"TCcategory"] intValue]);
            sqlite3_bind_int (statement, 25, [info[@"inTC"] intValue]);
            sqlite3_bind_int (statement, 26, [info[@"isDaemon"] intValue]);
            
            // After binding all values
            if (sqlite3_step(statement) != SQLITE_DONE) {
                const char *errorMsg = sqlite3_errmsg(database);
                if (strstr(errorMsg, "UNIQUE constraint failed") == NULL) {
                    NSLog(@"Failed to insert data for executable: %s", errorMsg);
                }
            }
        }
        else{
            NSLog(@"DB prepare error: %s", sqlite3_errmsg(database));
        }
        
        sqlite3_finalize(statement);
        
        // If isRunning, update the DB
        if ([info[@"isRunning"] intValue] != 0){
            // Prepare the SQL statement for updating the isRunning field
            const char *updateSQL = "UPDATE executables SET isRunning = ? WHERE path = ?";
            sqlite3_stmt *updateStatement;
            
            if (sqlite3_prepare_v2(database, updateSQL, -1, &updateStatement, NULL) == SQLITE_OK) {
                // Bind the new value for isRunning and the path of the executable
                sqlite3_bind_int(updateStatement, 1, [info[@"isRunning"] intValue]);
                sqlite3_bind_text(updateStatement, 2, absPath, -1, NULL);
                
                // Execute the update statement
                if (sqlite3_step(updateStatement) != SQLITE_DONE) {
                    const char *errorMsg = sqlite3_errmsg(database);
                    NSLog(@"Failed to update isRunning for executable: %s", errorMsg);
                }
            }
            else {
                NSLog(@"DB prepare error for update: %s", sqlite3_errmsg(database));
            }
            
            // Finalize the update statement
            sqlite3_finalize(updateStatement);
        }
        
        // Once the executable is inserted, move on to the libraries.
        BOOL libIsHijackable = false;
        NSArray *libraries = info[@"libraries"];
        for (NSDictionary *libInfo in libraries) {
            const char *insertExecutableSQL = "INSERT INTO libraries "
            "(path, executable_id, pathExists, isWeak, isDyld, isRelative, canCreate, isWritable, isHijackable) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
            sqlite3_stmt *statement;
            
            if (sqlite3_prepare_v2(database, insertExecutableSQL, -1, &statement, NULL) == SQLITE_OK) {
                NSString *relativePath = libInfo[@"path"];
                NSString *absolutePath = [relativePath stringByStandardizingPath];
                const char *absPath = [absolutePath UTF8String];
                
                // If a lib is Hijackable, set it
                if ([libInfo[@"isHijackable"] intValue]){
                    libIsHijackable = true;
                }
                
                sqlite3_bind_text(statement, 1, absPath, -1, NULL);
                sqlite3_bind_int (statement, 2, [libInfo[@"executable_id"] intValue]);
                sqlite3_bind_int (statement, 3, [libInfo[@"exists"] intValue]);
                sqlite3_bind_int (statement, 4, [libInfo[@"isWeak"] intValue]);
                sqlite3_bind_int (statement, 5, [libInfo[@"isDyld"] intValue]);
                sqlite3_bind_int (statement, 6, [libInfo[@"isRelative"] intValue]);
                sqlite3_bind_int (statement, 7, [libInfo[@"canCreate"] intValue]);
                sqlite3_bind_int (statement, 8, [libInfo[@"isWritable"] intValue]);
                sqlite3_bind_int (statement, 9, [libInfo[@"isHijackable"] intValue]);
                
                // After binding all values
                if (sqlite3_step(statement) != SQLITE_DONE) {
                    const char *errorMsg = sqlite3_errmsg(database);
                    if (strstr(errorMsg, "UNIQUE constraint failed") == NULL) {
                        NSLog(@"Failed to insert data for executable: %s", errorMsg);
                    }
                }
            }
            else{
                NSLog(@"DB prepare error: %s", sqlite3_errmsg(database));
            }
            
            // Now insert the relationship into the executable_libraries table
            const char *insertRelationshipSQL =
            "INSERT INTO executable_libraries (executable_path, library_path) "
            "VALUES (?, ?);";
            
            if (sqlite3_prepare_v2(database, insertRelationshipSQL, -1, &statement, NULL) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, [executable UTF8String], -1, NULL);
                sqlite3_bind_text(statement, 2, [libInfo[@"path"] UTF8String], -1, NULL);
                
                if (sqlite3_step(statement) != SQLITE_DONE) {
                    const char *errorMsg = sqlite3_errmsg(database);
                    if (strstr(errorMsg, "UNIQUE constraint failed") == NULL) {
                        NSLog(@"Failed to insert relationship for executable and library: %s", sqlite3_errmsg(database));
                    }
                }
            }
            else{
                NSLog(@"DB prepare error: %s", sqlite3_errmsg(database));
            }
            sqlite3_finalize(statement);
        }
        
        BOOL isElectron = false;
        NSString *bundle_path = [self findPathUntilFirstFolderWithExtension:absolutePath];
        bundle_path = [bundle_path stringByReplacingOccurrencesOfString:@"//" withString:@"/"];
        if ([bundle_path length] > 0){
            // Get if Electron
            NSString *electronFrameworkPath = [NSString stringWithFormat:@"%@/Contents/Frameworks/Electron Framework.framework", bundle_path];
            NSFileManager *fileManager = [NSFileManager defaultManager];
            // Electron if Electron Framework and binary in MacOS folder
            isElectron = [fileManager fileExistsAtPath:electronFrameworkPath] && [absolutePath hasPrefix:[NSString stringWithFormat:@"%@/Contents/MacOS/", bundle_path]];
            
            // Get if handler of any scheme or UTI
            NSArray *schemes = [allSchemes allKeysForObject:bundle_path];
            NSString *schemesString = @"";
            if (schemes.count > 0) {
                schemesString = [schemes componentsJoinedByString:@", "];
            }
            
            NSArray *utis = [allUTIs allKeysForObject:bundle_path];
            NSString *utisString = @"";
            if (schemes.count > 0) {
                utisString = [utis componentsJoinedByString:@", "];
            }
            
            const char *insertRelationshipSQL =
            "INSERT OR IGNORE INTO bundles (bundle_path, isElectron, schemes, utis) "
            "VALUES (?, ?, ?, ?);";
            
            if (sqlite3_prepare_v2(database, insertRelationshipSQL, -1, &statement, NULL) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, [bundle_path UTF8String], -1, NULL);
                sqlite3_bind_int (statement, 2, isElectron ? 1 : 0);
                sqlite3_bind_text(statement, 3, [schemesString UTF8String], -1, NULL);
                sqlite3_bind_text(statement, 4, [utisString UTF8String], -1, NULL);
                
                if (sqlite3_step(statement) != SQLITE_DONE) {
                    const char *errorMsg = sqlite3_errmsg(database);
                    if (strstr(errorMsg, "UNIQUE constraint failed") == NULL) {
                        NSLog(@"Failed to insert bundle: %s", sqlite3_errmsg(database));
                    }
                }
            }
            else{
                NSLog(@"DB prepare error: %s", sqlite3_errmsg(database));
            }
            sqlite3_finalize(statement);
            
            // Introduce the executable inside the bundle it belongs to
            const char *insertExecutableBundleSQL =
            "INSERT INTO executable_bundles (bundle_path, executable_path) "
            "VALUES (?, ?);";
            
            if (sqlite3_prepare_v2(database, insertExecutableBundleSQL, -1, &statement, NULL) == SQLITE_OK) {
                sqlite3_bind_text(statement, 1, [bundle_path UTF8String], -1, NULL);
                sqlite3_bind_text(statement, 2, absPath, -1, NULL);
                
                if (sqlite3_step(statement) != SQLITE_DONE) {
                    const char *errorMsg = sqlite3_errmsg(database);
                    if (strstr(errorMsg, "UNIQUE constraint failed") == NULL) {
                        NSLog(@"Failed to insert relationship for executable and bundle: %s", sqlite3_errmsg(database));
                    }
                }
            }
            else{
                NSLog(@"DB prepare error: %s", sqlite3_errmsg(database));
            }
            sqlite3_finalize(statement);
        }
        
        // Do some POST analysis
        BOOL noLibVal = [info[@"entitlements"] containsString:@"com.apple.security.cs.disable-library-validation"] ||
                        [info[@"entitlements"] containsString:@"com.apple.private.security.clear-library-validation"] || 
                        !info[@"isRestricted"];
        
        BOOL allowDyldEnv = [info[@"entitlements"] containsString:@"com.apple.security.cs.allow-dyld-environment-variables"] ||
                            ( !info[@"isSUID"] && !info[@"isSGID"] && !info[@"isRestricted"] );
        
        BOOL isDebugger = [info[@"entitlements"] containsString:@"com.apple.security.cs.debugger"];
        
        BOOL bypassSIP = [info[@"entitlements"] containsString:@"com.apple.rootless.install.heritable"] || [info[@"entitlements"] containsString:@"com.apple.rootless.install"];
        
        BOOL isProcInjector = [info[@"entitlements"] containsString:@"com.apple.system-task-ports"] || [info[@"entitlements"] containsString:@"task_for_pid-allow"];
        
        BOOL writeTCC = [info[@"entitlements"] containsString:@"com.apple.private.tcc.manager"] ||
                        [info[@"entitlements"] containsString:@"com.apple.rootless.storage.TCC"] ||
                        [info[@"entitlements"] containsString:@"kTCCServiceSystemPolicySysAdminFiles"] ||
                        [info[@"entitlements"] containsString:@"kTCCServiceEndpointSecurityClient"] ||
                        [info[@"tccPerms"] containsString:@"kTCCServiceSystemPolicySysAdminFiles"] ||
                        [info[@"tccPerms"] containsString:@"kTCCServiceEndpointSecurityClient"];
        
        BOOL writeSSV = [info[@"entitlements"] containsString:@"com.apple.private.apfs.revert-to-snapshot"] || [info[@"entitlements"] containsString:@"com.apple.private.apfs.create-sealed-snapshot"];
        
        BOOL isKextLoader = [info[@"entitlements"] containsString:@"com.apple.private.security.kext-management"];
        
        BOOL isFDA = [info[@"entitlements"] containsString:@"kTCCServiceSystemPolicyAllFiles"] || [info[@"tccPerms"] containsString:@"kTCCServiceSystemPolicyAllFiles"];
        
        BOOL modAutoTasks = [info[@"entitlements"] containsString:@"kTCCServiceAppleEvents"] || [info[@"tccPerms"] containsString:@"kTCCServiceAppleEvents"];
        
        BOOL canModifApps = [info[@"entitlements"] containsString:@"kTCCServiceSystemPolicyAppBundles"] || [info[@"tccPerms"] containsString:@"kTCCServiceSystemPolicyAppBundles"];
        
        BOOL canInstallApps = [info[@"entitlements"] containsString:@"system.install.apple-software"] && [info[@"entitlements"] containsString:@"system.install.apple-software.standar-user"];
        
        BOOL iCloudAccs = [info[@"entitlements"] containsString:@"com.apple.private.icloud-account-access"];
        
        
        // Check if the binary is privileged
        NSMutableArray *privilegedReasons = [[NSMutableArray alloc] init];
        NSString* privileged = @"Low";
        if (isDebugger || canModifApps || [info[@"entitlements"] containsString:@"com.apple.private.tcc.allow"] || 
            [info[@"entitlements"] containsString:@"kTCCServiceAll"] || [info[@"tccPerms"] containsString:@"kTCCServiceAll"]){
            
            if (isDebugger)
                [privilegedReasons addObject:@"isDebugger"];
            if (canModifApps)
                [privilegedReasons addObject:@"canModifApps"];
            if ([info[@"entitlements"] containsString:@"com.apple.private.tcc.allow"] ||
                [info[@"tccPerms"] containsString:@"kTCC"])
                [privilegedReasons addObject:@"containsTCC"];
            if ([info[@"entitlements"] containsString:@"kTCCServiceAll"] || [info[@"tccPerms"] containsString:@"kTCCServiceAll"])
                [privilegedReasons addObject:@"kTCCServiceAll"];

            privileged = @"Medium";
        }
        
        if (bypassSIP ||isProcInjector || writeTCC || writeSSV || isFDA || [info[@"isSGID"] intValue] || [info[@"isSUID"] intValue] || [info[@"isDaemon"] intValue] || isKextLoader || canInstallApps || modAutoTasks || iCloudAccs){
            [privilegedReasons removeAllObjects];
            privileged = @"High";
            
            if (bypassSIP)
                [privilegedReasons addObject:@"bypassSIP"];
            if (isProcInjector)
                [privilegedReasons addObject:@"isProcInjector"];
            if (writeTCC)
                [privilegedReasons addObject:@"writeTCC"];
            if (writeSSV)
                [privilegedReasons addObject:@"writeSSV"];
            if (isFDA)
                [privilegedReasons addObject:@"isFDA"];
            if ([info[@"isSGID"] intValue])
                [privilegedReasons addObject:@"isSGID"];
            if ([info[@"isSUID"] intValue])
                [privilegedReasons addObject:@"isSUID"];
            if ([info[@"isDaemon"] intValue])
                [privilegedReasons addObject:@"isDaemon"];
            if (isKextLoader)
                [privilegedReasons addObject:@"isKextLoader"];
            if (canInstallApps)
                [privilegedReasons addObject:@"canInstallApps"];
            if (modAutoTasks)
                [privilegedReasons addObject:@"modAutoTasks"];
            if (iCloudAccs)
                [privilegedReasons addObject:@"iCloudAccs"];
        }
        
        NSString *privilegeReasonsString = [privilegedReasons componentsJoinedByString:@", "];
        
        // Check if the app is injectable
        NSMutableArray *injectableReasons = [[NSMutableArray alloc] init];
        NSString* injectable = @"Low";
        if (noLibVal || allowDyldEnv || [info[@"entitlements"] containsString:@"com.apple.security.get-task-allow"] || libIsHijackable ){
            injectable = @"Medium";
            
            if (noLibVal)
                [injectableReasons addObject:@"noLibVal"];
            if (allowDyldEnv)
                [injectableReasons addObject:@"allowDyldEnv"];
            if ([info[@"entitlements"] containsString:@"com.apple.security.get-task-allow"])
                [injectableReasons addObject:@"GetTaskAllow"];
            if (libIsHijackable)
                [injectableReasons addObject:@"libIsHijackable"];
        }
        
        if ((noLibVal && allowDyldEnv) || (noLibVal && libIsHijackable) || isElectron){
            injectable = @"High";
            [injectableReasons removeAllObjects];
            
            if (noLibVal && allowDyldEnv)
                [injectableReasons addObject:@"noLibVal && allowDyldEnv"];
            if (noLibVal && libIsHijackable)
                [injectableReasons addObject:@"noLibVal && libIsHijackable"];
            if (isElectron)
                [injectableReasons addObject:@"isElectron"];
        }
        
        NSString *injectableReasonsString = [injectableReasons componentsJoinedByString:@", "];

        
        // Now insert the relationship into the executable_libraries table
        const char *insertRelationshipSQL =
        "UPDATE executables "
        "SET noLibVal = ?, "
        "allowDyldEnv = ?, "
        "isDebugger = ?, "
        "bypassSIP = ?, "
        "isProcInjector = ?, "
        "writeTCC = ?, "
        "writeSSV = ?, "
        "isKextLoader = ?, "
        "isFDA = ?, "
        "modAutoTasks = ?, "
        "canModifApps = ?, "
        "canInstallApps = ?, "
        "iCloudAccs = ?, "
        "privileged = ?, "
        "privilegedReasons = ?, "
        "injectable = ?, "
        "injectableReasons = ?"
        
        "WHERE path = ?;";
        
        if (sqlite3_prepare_v2(database, insertRelationshipSQL, -1, &statement, NULL) == SQLITE_OK) {
            sqlite3_bind_int (statement, 1, (int)noLibVal);
            sqlite3_bind_int (statement, 2, (int)allowDyldEnv);
            sqlite3_bind_int (statement, 3, (int)isDebugger);
            sqlite3_bind_int (statement, 4, (int)bypassSIP);
            sqlite3_bind_int (statement, 5, (int)isProcInjector);
            sqlite3_bind_int (statement, 6, (int)writeTCC);
            sqlite3_bind_int (statement, 7, (int)writeSSV);
            sqlite3_bind_int (statement, 8, (int)isKextLoader);
            sqlite3_bind_int (statement, 9, (int)isFDA);
            sqlite3_bind_int (statement, 10, (int)modAutoTasks);
            sqlite3_bind_int (statement, 11, (int)canModifApps);
            sqlite3_bind_int (statement, 12, (int)canInstallApps);
            sqlite3_bind_int (statement, 13, (int)iCloudAccs);
            sqlite3_bind_text(statement, 14, [privileged UTF8String], -1, NULL);
            sqlite3_bind_text(statement, 15, [privilegeReasonsString UTF8String], -1, NULL);
            sqlite3_bind_text(statement, 16, [injectable UTF8String], -1, NULL);
            sqlite3_bind_text(statement, 17, [injectableReasonsString UTF8String], -1, NULL);
            
            sqlite3_bind_text(statement, 18, absPath, -1, NULL);
            
            
            if (sqlite3_step(statement) != SQLITE_DONE) {
                const char *errorMsg = sqlite3_errmsg(database);
                if (strstr(errorMsg, "UNIQUE constraint failed") == NULL) {
                    NSLog(@"Failed to insert relationship for executable and library: %s", sqlite3_errmsg(database));
                }
            }
        }
        else{
            NSLog(@"DB prepare error: %s", sqlite3_errmsg(database));
        }
        sqlite3_finalize(statement);
    }
}


- (NSString *)findPathUntilFirstFolderWithExtension:(NSString *)absPath{
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSArray *pathComponents = [absPath pathComponents];
    NSMutableString *resultingPath = [NSMutableString string];
    
    for (NSString *component in pathComponents) {
        [resultingPath appendFormat:@"%@/", component];
        BOOL isDirectory;
        BOOL exists = [fileManager fileExistsAtPath:resultingPath isDirectory:&isDirectory];
        if (exists && isDirectory && [component pathExtension].length > 0) {
            return [resultingPath substringToIndex:resultingPath.length - 1];  // Remove trailing '/'
        }
    }
    return @"";  // Return nil if no such folder found
}


@end
