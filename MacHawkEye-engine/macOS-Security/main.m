// clang -framework Foundation -framework Security -lobjc -lsqlite3 *.m -o executable

#import <Foundation/Foundation.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <libkern/OSByteOrder.h>
#import "TechnologiesModule.h"
#import "EntitlementsModule.h"
#import "SUGIDModule.h"
#import "ACLsModule.h"
#import "ImportsModule.h"
#import "XAttrsModule.h"
#import "SQLiteModule.h"
#import "ProcessesModule.h"
#import "DaemonsModule.h"
#import "TrustCacheModule.h"
#import "HandlersModule.h"


@interface ExecutableChecker : NSObject
- (BOOL)hasValidMagicBytesAtPath:(NSString *)path;
- (void)findAndProcessExecutablesAtPath:(NSString *)path withprocBins:(NSArray<NSString *>*)procBins withVerbose:(bool)verbose;
- (void)processExecutable:(NSString *)executable withVerbose:(bool)verbose isRunning:(NSNumber *) isRunning isDaemon:(NSNumber *) isDaemon withMachSvcs:(NSString *)machSvcs;
- (NSArray<NSString *>*)processAllRunningExecutablesWithVerbose:(bool)verbose;
- (NSArray<NSString *>*)processDaemonsWithVerbose:(bool)verbose;
@end


@implementation ExecutableChecker

NSMutableDictionary *trust_cache_dict;
NSDictionary * all_utis;
NSDictionary * all_schemes;
NSString *userTCCDBPath = nil;
NSString *systemTCCDBPath = nil;
NSString *authDBPath = nil;

TechnologiesModule *techModule;
SUGIDModule *sugidModule;
XAttrsModule *xattrsModule;
ACLsModule *aclsModule;
EntitlementsModule *entitlementsModule;
ImportsModule *importsModule;
SQLiteModule *sqliteModule;
HandlersModule *handlersModule;


- (BOOL)hasValidMagicBytesAtPath:(NSString *)path {
    @autoreleasepool {
        FILE *file = fopen([path UTF8String], "r");
        if (!file) return NO;
        
        uint32_t magicBytes;
        fread(&magicBytes, sizeof(magicBytes), 1, file);
        
        BOOL isLittleEndian = (magicBytes == FAT_CIGAM);
        
        // Check for fat_macho
        if (magicBytes == FAT_MAGIC || magicBytes == FAT_CIGAM) {
            uint32_t nfat_arch;
            fread(&nfat_arch, sizeof(nfat_arch), 1, file);
            
            if (isLittleEndian) {
                nfat_arch = OSSwapInt32(nfat_arch);  // Swap if little-endian
            }
            
            // Read each fat_arch structure
            for (uint32_t i = 0; i < nfat_arch; i++) {
                struct fat_arch arch;
                fread(&arch, sizeof(struct fat_arch), 1, file);
                
                uint32_t offset = isLittleEndian ? OSSwapInt32(arch.offset) : arch.offset;
                fseek(file, offset, SEEK_SET);
                
                uint32_t archMagic;
                fread(&archMagic, sizeof(archMagic), 1, file);
                
                if (archMagic == 0xfeedface || archMagic == 0xfeedfacf) {
                    fseek(file, sizeof(uint32_t) * 2, SEEK_CUR); // Skip cputype, cpusubtype
                    uint32_t fileType;
                    fread(&fileType, sizeof(fileType), 1, file);
                    
                    if (fileType == MH_EXECUTE) {
                        fclose(file);
                        return YES;
                    }
                }
                
                // Reset file position to next fat_arch for next iteration
                fseek(file, sizeof(struct fat_header) + (sizeof(struct fat_arch) * (i + 1)), SEEK_SET);
            }
        }
        else if (magicBytes == 0xfeedface || magicBytes == 0xfeedfacf) { // Mach-O but not fat
            fseek(file, sizeof(uint32_t) * 2, SEEK_CUR); // Skip cputype, cpusubtype
            uint32_t fileType;
            fread(&fileType, sizeof(fileType), 1, file);
            
            if (fileType == MH_EXECUTE) {
                fclose(file);
                return YES;
            }
        }
        
        fclose(file);
        return NO;
    }
}


- (void)findAndProcessExecutablesAtPath:(NSString *)path withprocBins:(NSArray<NSString *>*)procBins withVerbose:(bool)verbose{
    NSLog(@"Searching for executables in %@...", path);
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSDirectoryEnumerator *enumerator = [fileManager enumeratorAtPath:path];
    
    NSArray* script_extensions = @[@".sh", @".py", @".pl", @".js", @".php"];

    NSString *file;
    while (file = [enumerator nextObject]) {
        @autoreleasepool {
            NSString *filePath = [path stringByAppendingPathComponent:file];
            
            // Pass certain paths
            if ([filePath hasPrefix:@"/System/Volumes/Data"] || [filePath hasPrefix:@"/dev/"]){
                continue;
            }
            
            // Check if it's a script
            BOOL isScript = NO;
            for (NSString *extension in script_extensions) {
                if ([filePath hasSuffix:extension]) {
                    [sqliteModule storeScriptInfo:path];
                    isScript = YES;
                    break;
                }
            }
            
            if (isScript){
                continue;
            }
            
            // Check if it's an executable
            if ( [[fileManager attributesOfItemAtPath:filePath error:nil][NSFileType] isEqualToString:NSFileTypeRegular] &&
                ![[filePath.pathExtension lowercaseString] isEqualToString:@"dylib"] &&
                [fileManager isExecutableFileAtPath:filePath] &&
                [self hasValidMagicBytesAtPath:filePath] &&
                ![procBins containsObject:filePath]) {
                
                [self processExecutable:filePath withVerbose:verbose isRunning:@0 isDaemon:@0 withMachSvcs:@""];
            }
        }
    }
    
    NSLog(@"Finished!");
}

- (NSArray<NSString *>*)processAllRunningExecutablesWithVerbose:(bool)verbose {
    @autoreleasepool {
        // Obtain all running executables
        ProcessModule *processModule = [[ProcessModule alloc] init];
        NSArray<NSString *> *executables = [processModule processRunningExecutablesWithVerbose:verbose];
        
        // Iterate through each executable and process it
        for (NSString *executable in executables) {
            [self processExecutable:executable
                        withVerbose:verbose
                          isRunning:@1
                           isDaemon:@0
                       withMachSvcs:@""];
        }
        return executables;
    }
}

- (NSArray<NSString *>*)processDaemonsWithVerbose:(bool)verbose{
    @autoreleasepool {
        // Obtain all deaemons executables
        DaemonsModule *daemonsModule = [[DaemonsModule alloc] init];
        NSArray<NSDictionary *> *daemons = [daemonsModule discoverDaemonsWithXPCServices];
        
        NSMutableArray<NSString *>* executablePaths = [[NSMutableArray alloc] init];
        
        // Iterate through each executable and process it
        for (NSDictionary *daemon in daemons) {
            NSString * executable = daemon[@"binaryPath"];
            NSString * machSvcs = daemon[@"machServices"];
            [self processExecutable:executable
                        withVerbose:verbose
                          isRunning:@0
                           isDaemon:@1
                       withMachSvcs:machSvcs];
            [executablePaths addObject:executable];  // Fixed the variable name here
        }
        
        return [executablePaths copy];
    }
}



- (void)processExecutable:(NSString *)executable withVerbose:(bool)verbose isRunning:(NSNumber *)isRunning isDaemon:(NSNumber *)isDaemon withMachSvcs:(NSString *)machSvcs{
    @autoreleasepool {
        NSDictionary *techInfo = [techModule getInfoForExecutable:executable];
        NSDictionary *sugidInfo = [sugidModule getInfoForExecutable:executable];
        NSDictionary *xatrsInfo = [xattrsModule getInfoForExecutable:executable];
        NSDictionary *aclsInfo = [aclsModule getInfoForExecutable:executable];
        NSDictionary *entitlementsInfo = [entitlementsModule getInfoForExecutable:executable withUsersTCCdb:userTCCDBPath withSystemTCCdb:systemTCCDBPath withAuthDB:authDBPath];
        NSDictionary *importsInfo = [importsModule getInfoForExecutable:executable isRestricted:[entitlementsInfo[@"isRestricted"] boolValue]];
        
        // Combine all the information into a single dictionary
        NSMutableDictionary *info = [NSMutableDictionary dictionary];
        [info addEntriesFromDictionary:techInfo];
        [info addEntriesFromDictionary:sugidInfo];
        [info addEntriesFromDictionary:xatrsInfo];
        [info addEntriesFromDictionary:aclsInfo];
        [info addEntriesFromDictionary:entitlementsInfo];
        [info addEntriesFromDictionary:importsInfo];
        info[@"isRunning"] = isRunning;
        info[@"machServices"] = machSvcs;
        
        // Check if cdhash inside trustcache
        NSInteger tc_category = 0;
        NSNumber* inTC = 0;
        if ([entitlementsInfo[@"cdhash"] length] > 0 && [trust_cache_dict objectForKey:entitlementsInfo[@"cdhash"]]) {
            tc_category = [[trust_cache_dict objectForKey:entitlementsInfo[@"cdhash"]] integerValue];
            inTC = @1;
        }
        NSNumber *tc_category_n = [NSNumber numberWithInteger:tc_category];
        info[@"TCcategory"] = tc_category_n;
        info[@"inTC"] = inTC;
        info[@"isDaemon"] = isDaemon;
        
        if (verbose){
            if (! [info[@"isRestricted"] boolValue]){
                NSLog(@"%@ is not restricted", executable);
            }
            if ([info[@"sandboxDefinition"] length] > 0){
                NSLog(@"%@ has a custom sandbox", executable);
            }
            if ([info[@"isInjectable"] boolValue]){
                NSLog(@"%@ is injectable", executable);
            }
            if ([info[@"canInjectOthers"] boolValue]){
                NSLog(@"%@ can inject others", executable);
            }
        }
        
        // Store the information in the SQLite database
        [sqliteModule storeInfo:info forExecutable:executable withAllUTIs:all_utis withAllSchemes:all_schemes];
    }
}
@end


void getUserTCCDBPathFromArgs(int argc, const char * argv[]) {
    for (int i = 1; i < argc; i++) {
        NSString *arg = [NSString stringWithUTF8String:argv[i]];

        if ([arg isEqualToString:@"--user-tcc-db"] && i + 1 < argc) {
            userTCCDBPath = [NSString stringWithUTF8String:argv[i + 1]];
            break;
        }
    }
}

void getSystemTCCDBPathFromArgs(int argc, const char * argv[]) {
    for (int i = 1; i < argc; i++) {
        NSString *arg = [NSString stringWithUTF8String:argv[i]];

        if ([arg isEqualToString:@"--system-tcc-db"] && i + 1 < argc) {
            systemTCCDBPath = [NSString stringWithUTF8String:argv[i + 1]];
            break;
        }
    }
}

void getAuthDBPathFromArgs(int argc, const char * argv[]) {
    for (int i = 1; i < argc; i++) {
        NSString *arg = [NSString stringWithUTF8String:argv[i]];

        if ([arg isEqualToString:@"--auth-db"] && i + 1 < argc) {
            authDBPath = [NSString stringWithUTF8String:argv[i + 1]];
            break;
        }
    }
}


int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // Parse command line arguments
        NSUserDefaults *args = [NSUserDefaults standardUserDefaults];
        NSArray *arguments = [[NSProcessInfo processInfo] arguments];
        
        // Get the path where the cli app must start looking for executables
        NSString *path = [args stringForKey:@"p"];
        NSArray *paths;
        
        NSString* helpMsg = @"Parameters supported:\n"
                             "\t-o <sqlite3 output path>\n"
                             "\t-p <path to check executables> -- OPTIONAL (By default '/')\n"
                             "\t--user-tcc-db <path to readable user TCC db> -- OPTIONAL (Nothing by default. Create a readable copy of $HOME/Library/Application Support/com.apple.TCC/TCC.db)\n"
                             "\t--system-tcc-db <path to readable system TCC db> -- OPTIONAL (Nothing by default. Create a readable copy of /Library/Application Support/com.apple.TCC/TCC.db)\n"
                             "\t--auth-db <path to readable auth db> -- OPTIONAL (Nothing by default. Create a readable copy of /var/db/auth.db)\n"
                             "\t--verbose -- OPTIONAL\n"
                             "\t--no-processes -- OPTIONAL (By default, check executables being executed)\n"
                             "\t--no-daemons -- OPTIONAL (By default, check executables of daemons)\n"
                             "\t--help/-h -- OPTIONAL (Get this help message)\n"
        ;
        
        BOOL help = [arguments containsObject:@"-h"] || [arguments containsObject:@"--help"];
        if (help){
            NSLog(@"%@", helpMsg);
            return 0;
        }

        
        if (!path) {
            NSLog(@"Path not provided. Using default paths.");
            paths = @[@"/"];
            /*paths = @[@"/usr/bin/",
                    @"/usr/sbin/",
                    @"/usr/local/bin/",
                    @"/usr/local/sbin/",
                    @"/bin/",
                    @"/sbin/",
                    @"/System/Library/CoreServices/",
                    @"/System/Library/PrivateFrameworks/",
                    @"/Applications/",
                    @"/usr/libexec/",
                    @"/opt/homebrew/bin",
                    @"/opt/homebrew/sbin"
            ];*/
            
        } else {
            paths = @[path];
        }
        
        // Get the path where the sqlite db must be stored
        NSString *output = [args stringForKey:@"o"];
        if (!output) {
            NSLog(@"Please provide an output path with the -o option.");
            NSLog(@"%@", helpMsg);
            return 1;
        }
        
        // Get user TCC db path
        getUserTCCDBPathFromArgs(argc, argv);
        if (userTCCDBPath == nil){
            NSLog(@"%@", @"No User TCC DB path indicated, no TCC info is going to be obtained from here. You will get false negatives.");
        }
        else{
            NSFileManager *fileManager = [NSFileManager defaultManager];
            BOOL isDir;
            BOOL fileExists = [fileManager fileExistsAtPath:userTCCDBPath isDirectory:&isDir];

            if (!fileExists) {
                NSLog(@"%@", @"The specified User TCC DB path does not exist.");
                return 1;
            } else if (isDir) {
                NSLog(@"%@", @"The specified User TCC DB path is a directory, not a file.");
                return 1;
            } else if (![fileManager isReadableFileAtPath:userTCCDBPath]) {
                NSLog(@"%@", @"The file at the specified User TCC DB path is not readable.");
                return 1;
            }
        }
        
        // Get system TCC db path
        getSystemTCCDBPathFromArgs(argc, argv);
        if (systemTCCDBPath == nil){
            NSLog(@"%@", @"No System TCC DB path indicated, no TCC info is going to be obtained from here. You will get false negatives.");
        }
        else{
            NSFileManager *fileManager = [NSFileManager defaultManager];
            BOOL isDir;
            BOOL fileExists = [fileManager fileExistsAtPath:systemTCCDBPath isDirectory:&isDir];

            if (!fileExists) {
                NSLog(@"%@", @"The specified System TCC DB path does not exist.");
                return 1;
            } else if (isDir) {
                NSLog(@"%@", @"The specified System TCC DB path is a directory, not a file.");
                return 1;
            } else if (![fileManager isReadableFileAtPath:systemTCCDBPath]) {
                NSLog(@"%@", @"The file at the specified System TCC DB path is not readable.");
                return 1;
            }
        }
        
        // Get auth db
        getAuthDBPathFromArgs(argc, argv);
        if (authDBPath == nil){
            NSLog(@"%@", @"No Auth DB path indicated, some info will be incomplete.");
        }
        else{
            NSFileManager *fileManager = [NSFileManager defaultManager];
            BOOL isDir;
            BOOL fileExists = [fileManager fileExistsAtPath:authDBPath isDirectory:&isDir];

            if (!fileExists) {
                NSLog(@"%@", @"The specified auth DB path does not exist.");
                return 1;
            } else if (isDir) {
                NSLog(@"%@", @"The specified auth DB path is a directory, not a file.");
                return 1;
            } else if (![fileManager isReadableFileAtPath:authDBPath]) {
                NSLog(@"%@", @"The file at the specified auth DB path is not readable.");
                return 1;
            }
        }
        
        // Get the verbose option
        BOOL verbose = [arguments containsObject:@"--verbose"];
        
        // Get the no process option
        BOOL no_processes = [arguments containsObject:@"--no-processes"];
        
        // Get the no daemons option
        BOOL no_daemons = [arguments containsObject:@"--no-daemons"];
        
        // Initialize global objects
        techModule = [[TechnologiesModule alloc] init];
        sugidModule = [[SUGIDModule alloc] init];
        xattrsModule = [[XAttrsModule alloc] init];
        aclsModule = [[ACLsModule alloc] init];
        entitlementsModule = [[EntitlementsModule alloc] init];
        importsModule = [[ImportsModule alloc] init];
        sqliteModule = [[SQLiteModule alloc] initWithDatabasePath:output];
        
        if (!sqliteModule) {
            NSLog(@"Error using SQLite database in %@", output);
            exit(1);
        }
        
        // Get TrustCache information
        TrustCacheModule *trustcachechecker = [[TrustCacheModule alloc] init];
        trust_cache_dict = [trustcachechecker processFiles];
        
        // Get handlers info
        all_utis = [HandlersModule getAllUTIs];
        all_schemes = [HandlersModule getAllSchemes];
       
        // Prepate to call the relevant functions
        ExecutableChecker *checker = [[ExecutableChecker alloc] init];
        
        // Get daemons bins info
        NSArray<NSString *>* daemon_bins = [[NSMutableArray alloc] init];
        if (!no_daemons){
            daemon_bins = [checker processDaemonsWithVerbose:verbose];
        }
        
        // Get procs bin info
        NSArray<NSString *>* proc_bins = [[NSMutableArray alloc] init];
        if (!no_processes){
            proc_bins = [checker processAllRunningExecutablesWithVerbose:verbose];
        }
        
        // Combine procs and bin executable lists
        NSMutableSet<NSString *> *combinedSet = [NSMutableSet setWithArray:proc_bins];
        [combinedSet addObjectsFromArray:daemon_bins];
        NSArray<NSString *> *procBins = [combinedSet allObjects];
        
        // Search bins and process them
        for (NSString *path in paths) {
            [checker findAndProcessExecutablesAtPath:path withprocBins:procBins withVerbose:verbose];
        }
        
        return 0;
    }
}



/*
 Relevant queries for executables:
 SELECT path FROM executables WHERE acls != "";
 SELECT path FROM executables where isRestricted=0;
 SELECT path FROM executables where isRestricted=0 and isAppleBin=0; -- Vuln to injection
 SELECT path FROM executables where entitlements like "%com.apple.security.get-task-allow%"; -- Vuln to injection
 SELECT path FROM executables where entitlements like "%com.apple.security.cs.disable-library-validation%"; -- Vuln to injection
 SELECT path FROM executables where entitlements like "%com.apple.security.cs.allow-dyld-environment-variables%"; -- Vuln to injection
 SELECT path FROM executables where entitlements like "%com.apple.system-task-ports%"; -- Check if we can use any of the tools here to read proc memory or write
 SELECT path FROM executables where entitlements like "%com.apple.security.cs.debugger%";
 SELECT path FROM executables where sandboxDefinition != "";
 
 
 
 
 # Dylib injection queries
 
 ## Get Hijackable (Dyld hijack & Dlopen hijack) binaries:
 ### Unexploitable unless you can modify apps...
 SELECT e.path, e.privileged, e.privilegedReasons, l.path
 FROM executables e
 JOIN executable_libraries el ON e.path = el.executable_path
 JOIN libraries l ON el.library_path = l.path
 WHERE l.isHijackable = 1 AND e.noLibVal = 1;
  
 ## Get other potential Dlopen hijackable binaries (potentially root needed to create the file):
 SELECT e.path, e.privileged, e.privilegedReasons, l.path
 FROM executables e
 JOIN executable_libraries el ON e.path = el.executable_path
 JOIN libraries l ON el.library_path = l.path
 WHERE l.isDyld = 0 AND l.pathExists = 0 AND l.isHijackable = 0 AND e.noLibVal = 1;
 
 
 ## Get DYLD_INSERT_LIBRARIES
 SELECT e.path, e.privileged, e.privilegedReasons
 FROM executables e
 WHERE e.noLibVal = 1 AND e.allowDyldEnv = 1;
 
 ## Check non apple apps with high privileges, no library validation, not apple and with relative imports to abuse them
 SELECT e.path, e.privileged, e.privilegedReasons, l.path
 FROM executables e
 JOIN executable_libraries el ON e.path = el.executable_path
 JOIN libraries l ON el.library_path = l.path
 WHERE e.noLibVal=1 AND e.privileged="High" AND NOT e.isAppleBin AND l.isRelative AND NOT e.privilegedReasons="isDaemon";
 
 
 
 # Mach Port Injection
 
 ## Get processes that can be injected
 SELECT path, privileged, privilegedReasons, injectable, injectableReasons
 FROM executables
 WHERE injectableReasons LIKE "%GetTaskAllow%";
 
 ## Get privileged processes that can inject anything but the kernel and are injectable
 SELECT path, privileged, privilegedReasons, injectable, injectableReasons
 FROM executables
 WHERE isProcInjector AND injectable <> "Low";
 
 
 # Bundles
 
 SELECT b.bundle_path, b.schemes, e.path, e.privileged, e.privilegedReasons
 FROM executables e
 JOIN executable_bundles eb ON e.path = eb.executable_path
 JOIN bundles b ON eb.bundle_path = b.bundle_path
 WHERE b.schemes != "" AND e.privileged != "Low"
 
 */
