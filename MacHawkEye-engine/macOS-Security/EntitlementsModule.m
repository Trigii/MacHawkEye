#import "EntitlementsModule.h"
#import <Security/Security.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <sqlite3.h>


@implementation EntitlementsModule

- (NSDictionary *)getInfoForExecutable:(NSString *)executable
                        withUsersTCCdb:(NSString *)usersTCCdb
                       withSystemTCCdb:(NSString *)systemTCCdb
                            withAuthDB:(NSString *)authDBpath{
    @autoreleasepool {
        NSMutableDictionary *info = [NSMutableDictionary dictionary];
        
        SecStaticCodeRef staticCode = NULL;
        OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:executable], kSecCSDefaultFlags, &staticCode);
        if (status != errSecSuccess || staticCode == NULL) {
            NSLog(@"Failed to create static code reference with error: %d", (int)status);
            return nil;
        }
        
        CFDictionaryRef entitlements = NULL;
        status = SecCodeCopySigningInformation(staticCode, kSecCSSigningInformation, &entitlements);
        if (status != errSecSuccess || entitlements == NULL) {
            NSLog(@"Failed to get signing information with error: %d", (int)status);
            CFRelease(staticCode);  // Release staticCode before returning
            return nil;
        }
        
        NSDictionary *entitlementsDict = (__bridge NSDictionary *)entitlements;
        
        // Team & identifier
        [info setObject:entitlementsDict[@"teamid"] ?: @"" forKey:@"teamid"];
        
        NSString *exec_id = entitlementsDict[@"identifier"];
        [info setObject:exec_id ?: @"" forKey:@"identifier"];
        
        //cdhash
        NSData *data = entitlementsDict[@"cdhashes"][0];
        NSMutableString *byteString = [NSMutableString stringWithCapacity:data.length * 2];
        const unsigned char *bytes = data.bytes;
        for (NSInteger i = 0; i < data.length; i++) {
            [byteString appendFormat:@"%02x", bytes[i]];
        }
        NSString *lowercaseCDHash = [byteString lowercaseString];
        [info setObject:lowercaseCDHash forKey:@"cdhash"];
        
        // Check if sandbox directory exists
        BOOL isInSbxContainer = [self isIdentifierInSandboxContainer:exec_id];
        [info setObject:@(isInSbxContainer) forKey:@"inSbxContainer"];
        
        // Check if belongs to Apple
        [info setObject:@([self isAppleIdentifier:exec_id]) forKey:@"isAppleBin"];
        
        // Check for XPC rules
        NSString *result = [self rulesForBundleID:exec_id withAuthDB:authDBpath];
        [info setObject:result forKey:@"xpcRules"];
        
        // Signing flags
        NSInteger flagsInt = [entitlementsDict[@"flags"] integerValue];
        NSArray *flagsStrings = [self getStringFlagsFromInteger:flagsInt];
        NSString *joinedflagsStrings = (flagsStrings.count > 0) ? [flagsStrings componentsJoinedByString:@", "] : @"";
        [info setObject:joinedflagsStrings ?: @"" forKey:@"flagsStrings"];
        [info setObject:@(flagsInt) forKey:@"flags"];
        
        BOOL isLoadLibraryRestricted = [self isLoadLibraryRestrictedByFlags:flagsInt] || [self hasRestrictHeaderSection:executable];
        [info setObject:@(isLoadLibraryRestricted) forKey:@"isRestricted"];
        
        // Entitlements
        // Convert the dictionary to JSON data
        NSDictionary *entitlements_dict = entitlementsDict[@"entitlements-dict"];
        NSError *error;
        NSString *jsonString = @"";
        NSArray *sandboxDefinitionArray = @[];
        if (entitlements_dict != nil) {
            NSData *jsonData = [NSJSONSerialization dataWithJSONObject:entitlements_dict options:0 error:&error];

            if (!jsonData) {
                NSLog(@"Failed to serialize entitlements dictionary from %@ to JSON: %@", executable, error);
                jsonString = @"{}";  // Empty dictionary in JSON format
            } else {
                jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
            }

            id sandboxDefinitionObject = entitlements_dict[@"com.apple.security.temporary-exception.sbpl"];
            if (!sandboxDefinitionObject) {
                sandboxDefinitionArray = @[]; // Ensure it is an empty array if the key doesn't exist
            } else if ([sandboxDefinitionObject isKindOfClass:[NSArray class]]) {
                sandboxDefinitionArray = (NSArray *)sandboxDefinitionObject;
            } else if ([sandboxDefinitionObject isKindOfClass:[NSString class]]) {
                sandboxDefinitionArray = @[sandboxDefinitionObject]; // Convert NSString to NSArray with a single element
            }
        }

        [info setObject:jsonString forKey:@"entitlements"];

        NSString *joinedSandboxDefinitions;
        if ([sandboxDefinitionArray count] > 0) {
            joinedSandboxDefinitions = [sandboxDefinitionArray componentsJoinedByString:@"\n"];
        } else {
            joinedSandboxDefinitions = @"";
        }
        
        [info setObject:joinedSandboxDefinitions forKey:@"sandboxDefinition"];
        
        // TCC perms from database
        NSString* tccPerms = [self getAllTCCPermissionsForBundle:exec_id withUsersTCCdb:usersTCCdb  withSystemTCCdb:systemTCCdb];
        [info setObject:tccPerms forKey:@"tccPerms"];
        
        // Cert info
        NSString *certificateDetails = [self getCertificateDetailsForExecutable:executable];
        [info setObject:certificateDetails ?: @"" forKey:@"certificateDetails"];
        
        CFRelease(entitlements);
        CFRelease(staticCode);
        
        return info;
    }
    /*
     {
     "teamid": "string",
     "identifier": "string",
     "isAppleBin": bool,
     "flags": int,
     "flagsStrings": "string",
     "isRestricted": bool,
     "entitlements": "string",
     "sandboxDefinition": "string",
     "isInjectable": bool,
     "canInjectOthers": bool,
     "certificateDetails": "string",
     }
     */
}

- (NSString *)getCertificateDetailsForExecutable:(NSString *)executable {
    NSMutableArray *certificateDetails = [NSMutableArray array];
    SecStaticCodeRef staticCode;
    
    OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:executable], kSecCSDefaultFlags, &staticCode);
    if (status != errSecSuccess) {
        NSLog(@"Error creating static code: %d", status);
        return @"";
    }
    
    CFDictionaryRef signingInfo;
    @try {
        SecCodeCopySigningInformation(staticCode, kSecCSSigningInformation, &signingInfo);
    }
    @catch (NSException *exception) {
        NSLog(@"Caught exception: %@", exception);
        return @"";
    }
    
    if (signingInfo != NULL) {
        NSArray *certificates = (__bridge NSArray *)CFDictionaryGetValue(signingInfo, kSecCodeInfoCertificates);
        
        for (NSInteger i = 0; i < certificates.count; i++) {
            SecCertificateRef certificate = (__bridge SecCertificateRef)certificates[i];
            
            CFStringRef cn;
            SecCertificateCopyCommonName(certificate, &cn);
            
            CFStringRef issuerName = NULL;
            if (i < certificates.count - 1) {
                SecCertificateRef issuerCertificate = (__bridge SecCertificateRef)certificates[i + 1];
                SecCertificateCopyCommonName(issuerCertificate, &issuerName);
            }
            
            NSDictionary *certDetail = @{
                @"CN": (__bridge NSString *)(cn ? cn : CFSTR("")),
                @"CA": (__bridge NSString *)(issuerName ? issuerName : CFSTR(""))
            };
            [certificateDetails addObject:certDetail];
            
            if (cn) CFRelease(cn);
            if (issuerName) CFRelease(issuerName);
        }
        
        CFRelease(signingInfo);
    }
    CFRelease(staticCode);
    
    // Convert the array to JSON string
    NSError *error = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:certificateDetails options:0 error:&error];
    
    if (error) {
        NSLog(@"Failed to serialize data into JSON: %@", error.localizedDescription);
        return nil; // or return error message or handle differently
    }
    
    NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    return jsonString;
}

- (BOOL)isIdentifierInSandboxContainer:(NSString *)exec_id {
    // Construct the path to ~/Library/Containers/<identifier>
    NSString *homeDir = NSHomeDirectory();
    NSString *containersPath = [homeDir stringByAppendingPathComponent:@"Library/Containers"];
    NSString *identifierPath = [containersPath stringByAppendingPathComponent:exec_id];
    
    // Check if the sandbox directory exists at the constructed path
    NSFileManager *fileManager = [NSFileManager defaultManager];
    BOOL isDirectory;
    BOOL exists = [fileManager fileExistsAtPath:identifierPath isDirectory:&isDirectory];
    
    return (exists && isDirectory);
}


- (BOOL)isLoadLibraryRestrictedByFlags:(NSInteger)flags {
    return (flags & CS_FORCED_LV) || (flags & CS_RESTRICT) || (flags & CS_RUNTIME);
}

- (NSString *)rulesForBundleID:(NSString *)bundleID withAuthDB:(NSString *)authDBpath {
    // Check if the user is root
    if (authDBpath == nil) {
        return @"{}"; // Return empty JSON string if not root
    }
    
    // Open SQLite database at /var/db/auth.db
    sqlite3 *db;
    sqlite3_stmt *stmt;
    NSMutableArray *allRules = [NSMutableArray array];
    
    if (sqlite3_open([authDBpath UTF8String], &db) == SQLITE_OK) {
        NSString *query = [NSString stringWithFormat:@"SELECT name FROM rules WHERE name LIKE '%@.%%';", bundleID];
        if (sqlite3_prepare_v2(db, [query UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char *ruleName = sqlite3_column_text(stmt, 0);
                NSString *ruleString = [NSString stringWithUTF8String:(const char *)ruleName];
                [allRules addObject:ruleString];
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
    
    NSMutableDictionary *results = [NSMutableDictionary dictionary];
    for (NSString *rule in allRules) {
        NSString *ruleResult = [self ruleValueForIdentifier:rule];
        if (ruleResult) {
            [results setObject:ruleResult forKey:rule];
        }
    }
    
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:results options:0 error:&error];
    
    if (!jsonData) {
        NSLog(@"Error: %@", error.localizedDescription);
        return @"{}";
    }
    
    return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
}

- (NSString *)ruleValueForIdentifier:(NSString *)identifier {
    NSString *command = [NSString stringWithFormat:@"security authorizationdb read %@", identifier];
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:@"/bin/sh"];
    [task setArguments:@[@"-c", command]];
    
    NSPipe *pipe = [NSPipe pipe];
    [task setStandardOutput:pipe];
    [task launch];
    
    NSData *data = [[pipe fileHandleForReading] readDataToEndOfFile];
    [task waitUntilExit];
    
    NSError *error = nil;
    NSPropertyListFormat format;
    NSDictionary *plist = [NSPropertyListSerialization propertyListWithData:data
                                                                    options:NSPropertyListImmutable
                                                                     format:&format
                                                                      error:&error];
    
    if (error) {
        NSLog(@"Error: %@", error.localizedDescription);
        return nil;
    }
    
    NSArray *rules = plist[@"rule"];
    if (rules && rules.count > 0) {
        return rules.lastObject; // assuming you want the last item in the array
    }
    
    return nil;
}


- (BOOL)hasRestrictSegmentInMachO:(int)fd {
    struct mach_header_64 header;
    ssize_t bytesRead = read(fd, &header, sizeof(struct mach_header_64));
    
    if (bytesRead != sizeof(struct mach_header_64) || header.magic != MH_MAGIC_64) {
        return NO;
    }
    
    for (uint32_t i = 0; i < header.ncmds; i++) {
        
        struct load_command cmd;
        read(fd, &cmd, sizeof(struct load_command));
        
        if (cmd.cmd == LC_SEGMENT_64) {
            // Seek back to start of the segment command since we already read cmd and cmdsize
            lseek(fd, -sizeof(struct load_command), SEEK_CUR);
            
            struct segment_command_64 segment;
            read(fd, &segment, sizeof(struct segment_command_64));
            
            if (strcmp(segment.segname, "__RESTRICT") == 0) {
                return YES;
            }
            
            lseek(fd, cmd.cmdsize - sizeof(struct segment_command_64), SEEK_CUR);
        }
        else {
            // Skip the rest of the command
            lseek(fd, cmd.cmdsize - sizeof(struct load_command), SEEK_CUR);
        }
    }
    return NO;
}

- (BOOL)hasRestrictHeaderSection:(NSString *)path {
    int fd = open([path UTF8String], O_RDONLY);
    if (fd == -1) return NO;
    
    struct fat_header fatHeader;
    read(fd, &fatHeader, sizeof(struct fat_header));
    
    if (fatHeader.magic == OSSwapInt32(FAT_MAGIC) || fatHeader.magic == OSSwapInt32(FAT_CIGAM)) {
        uint32_t archCount = OSSwapBigToHostInt32(fatHeader.nfat_arch);
        for (uint32_t i = 0; i < archCount; i++) {
            struct fat_arch arch;
            read(fd, &arch, sizeof(struct fat_arch));
            
            // Seek to the offset of this architecture's Mach-O binary and analyze it
            off_t archOffset = OSSwapBigToHostInt32(arch.offset);
            lseek(fd, archOffset, SEEK_SET);
            
            if ([self hasRestrictSegmentInMachO:fd]) {
                close(fd);
                return YES;
            }
        }
    } else {
        // It's not a fat binary, treat it as a regular Mach-O
        lseek(fd, 0, SEEK_SET);
        BOOL result = [self hasRestrictSegmentInMachO:fd];
        close(fd);
        return result;
    }
    
    close(fd);
    return NO;
}

- (BOOL)isAppleIdentifier:(NSString *)identifier {
    return [identifier hasPrefix:@"com.apple"];
}

- (NSArray *)getStringFlagsFromInteger:(NSInteger)flags {
    NSMutableArray *flagsArray = [NSMutableArray array];
    
    if (flags & CS_VALID) [flagsArray addObject:@"CS_VALID"];
    if (flags & CS_ADHOC) [flagsArray addObject:@"CS_ADHOC"];
    if (flags & CS_GET_TASK_ALLOW) [flagsArray addObject:@"CS_GET_TASK_ALLOW"];
    if (flags & CS_INSTALLER) [flagsArray addObject:@"CS_INSTALLER"];
    if (flags & CS_FORCED_LV) [flagsArray addObject:@"CS_FORCED_LV"];
    if (flags & CS_INVALID_ALLOWED) [flagsArray addObject:@"CS_INVALID_ALLOWED"];
    if (flags & CS_HARD) [flagsArray addObject:@"CS_HARD"];
    if (flags & CS_KILL) [flagsArray addObject:@"CS_KILL"];
    if (flags & CS_CHECK_EXPIRATION) [flagsArray addObject:@"CS_CHECK_EXPIRATION"];
    if (flags & CS_RESTRICT) [flagsArray addObject:@"CS_RESTRICT"];
    if (flags & CS_ENFORCEMENT) [flagsArray addObject:@"CS_ENFORCEMENT"];
    if (flags & CS_REQUIRE_LV) [flagsArray addObject:@"CS_REQUIRE_LV"];
    if (flags & CS_ENTITLEMENTS_VALIDATED) [flagsArray addObject:@"CS_ENTITLEMENTS_VALIDATED"];
    if (flags & CS_NVRAM_UNRESTRICTED) [flagsArray addObject:@"CS_NVRAM_UNRESTRICTED"];
    if (flags & CS_RUNTIME) [flagsArray addObject:@"CS_RUNTIME"];
    if (flags & CS_LINKER_SIGNED) [flagsArray addObject:@"CS_LINKER_SIGNED"];
    if (flags & CS_EXEC_SET_HARD) [flagsArray addObject:@"CS_EXEC_SET_HARD"];
    if (flags & CS_EXEC_SET_KILL) [flagsArray addObject:@"CS_EXEC_SET_KILL"];
    if (flags & CS_EXEC_SET_ENFORCEMENT) [flagsArray addObject:@"CS_EXEC_SET_ENFORCEMENT"];
    if (flags & CS_EXEC_INHERIT_SIP) [flagsArray addObject:@"CS_EXEC_INHERIT_SIP"];
    if (flags & CS_KILLED) [flagsArray addObject:@"CS_KILLED"];
    if (flags & CS_DYLD_PLATFORM) [flagsArray addObject:@"CS_DYLD_PLATFORM"];
    if (flags & CS_PLATFORM_BINARY) [flagsArray addObject:@"CS_PLATFORM_BINARY"];
    if (flags & CS_PLATFORM_PATH) [flagsArray addObject:@"CS_PLATFORM_PATH"];
    if (flags & CS_DEBUGGED) [flagsArray addObject:@"CS_DEBUGGED"];
    if (flags & CS_SIGNED) [flagsArray addObject:@"CS_SIGNED"];
    if (flags & CS_DEV_CODE) [flagsArray addObject:@"CS_DEV_CODE"];
    if (flags & CS_DATAVAULT_CONTROLLER) [flagsArray addObject:@"CS_DATAVAULT_CONTROLLER"];
    
    return flagsArray;
}



// From https://llvm.org/doxygen/BinaryFormat_2MachO_8h_source.html
enum CodeSignAttrs {
    CS_VALID = 0x00000001,          /* dynamically valid */
    CS_ADHOC = 0x00000002,          /* ad hoc signed */
    CS_GET_TASK_ALLOW = 0x00000004, /* has get-task-allow entitlement */
    CS_INSTALLER = 0x00000008,      /* has installer entitlement */
    
    CS_FORCED_LV =
    0x00000010, /* Library Validation required by Hardened System Policy */
    CS_INVALID_ALLOWED = 0x00000020, /* (macOS Only) Page invalidation allowed by
                                      task port policy */
    
    CS_HARD = 0x00000100,             /* don't load invalid pages */
    CS_KILL = 0x00000200,             /* kill process if it becomes invalid */
    CS_CHECK_EXPIRATION = 0x00000400, /* force expiration checking */
    CS_RESTRICT = 0x00000800,         /* tell dyld to treat restricted */
    
    CS_ENFORCEMENT = 0x00001000, /* require enforcement */
    CS_REQUIRE_LV = 0x00002000,  /* require library validation */
    CS_ENTITLEMENTS_VALIDATED =
    0x00004000, /* code signature permits restricted entitlements */
    CS_NVRAM_UNRESTRICTED =
    0x00008000, /* has com.apple.rootless.restricted-nvram-variables.heritable
                 entitlement */
    
    CS_RUNTIME = 0x00010000,       /* Apply hardened runtime policies */
    CS_LINKER_SIGNED = 0x00020000, /* Automatically signed by the linker */
    
    CS_ALLOWED_MACHO =
    (CS_ADHOC | CS_HARD | CS_KILL | CS_CHECK_EXPIRATION | CS_RESTRICT |
     CS_ENFORCEMENT | CS_REQUIRE_LV | CS_RUNTIME | CS_LINKER_SIGNED),
    
    CS_EXEC_SET_HARD = 0x00100000, /* set CS_HARD on any exec'ed process */
    CS_EXEC_SET_KILL = 0x00200000, /* set CS_KILL on any exec'ed process */
    CS_EXEC_SET_ENFORCEMENT =
    0x00400000, /* set CS_ENFORCEMENT on any exec'ed process */
    CS_EXEC_INHERIT_SIP =
    0x00800000, /* set CS_INSTALLER on any exec'ed process */
    
    CS_KILLED = 0x01000000, /* was killed by kernel for invalidity */
    CS_DYLD_PLATFORM =
    0x02000000, /* dyld used to load this is a platform binary */
    CS_PLATFORM_BINARY = 0x04000000, /* this is a platform binary */
    CS_PLATFORM_PATH =
    0x08000000, /* platform binary by the fact of path (osx only) */
    
    CS_DEBUGGED = 0x10000000, /* process is currently or has previously been
                               debugged and allowed to run with invalid pages */
    CS_SIGNED = 0x20000000, /* process has a signature (may have gone invalid) */
    CS_DEV_CODE =
    0x40000000, /* code is dev signed, cannot be loaded into prod signed code
                 (will go away with rdar://problem/28322552) */
    CS_DATAVAULT_CONTROLLER =
    0x80000000, /* has Data Vault controller entitlement */
    
    CS_ENTITLEMENT_FLAGS = (CS_GET_TASK_ALLOW | CS_INSTALLER |
                            CS_DATAVAULT_CONTROLLER | CS_NVRAM_UNRESTRICTED),
};


- (NSString *)getAllTCCPermissionsForBundle:(NSString *)bundleID
                          withUsersTCCdb:(NSString *)usersTCCdb
                        withSystemTCCdb:(NSString *)systemTCCdb {
    
    NSMutableSet *permissions = [[NSMutableSet alloc] init]; // Using a set to avoid duplicate entries

    // Helper block to query database and add results to permissions
    void (^queryDatabase)(NSString *) = ^(NSString *dbPath) {
        sqlite3 *db;
        if (sqlite3_open([dbPath UTF8String], &db) == SQLITE_OK) {
            NSString *query = [NSString stringWithFormat:@"SELECT service FROM access WHERE client='%@' AND auth_value > 1;", bundleID];
            sqlite3_stmt *statement;

            if (sqlite3_prepare_v2(db, [query UTF8String], -1, &statement, nil) == SQLITE_OK) {
                while (sqlite3_step(statement) == SQLITE_ROW) {
                    char *service = (char *)sqlite3_column_text(statement, 0);
                    if (service != NULL) {
                        [permissions addObject:[NSString stringWithUTF8String:service]];
                    }
                }
                sqlite3_finalize(statement);
            }
            sqlite3_close(db);
        }
    };

    if (usersTCCdb != nil) {
        // Query the user TCC database
        queryDatabase(usersTCCdb);
    }
    
    if (systemTCCdb != nil) {
        // Query the system TCC database
        queryDatabase(systemTCCdb);
    }

    // Combine the permissions into a string
    return [[permissions allObjects] componentsJoinedByString:@", "];
}

@end
