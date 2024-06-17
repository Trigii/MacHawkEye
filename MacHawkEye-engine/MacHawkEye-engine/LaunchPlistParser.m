#import "LaunchPlistParser.h"

@implementation LaunchPlistParser

- (NSArray<NSString *> *)launchPlistPaths {
    NSString *userLibraryPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Library"];
    return @[
        @"/Library/LaunchAgents",
        @"/Library/LaunchDaemons",
        @"/System/Library/LaunchAgents",
        @"/System/Library/LaunchDaemons",
        [userLibraryPath stringByAppendingPathComponent:@"LaunchAgents"],
        [userLibraryPath stringByAppendingPathComponent:@"LaunchDaemons"]
    ];
}

- (NSDictionary<NSString *, NSDictionary *> *)parseAllLaunchPlists {
    @autoreleasepool {
        NSMutableDictionary<NSString *, NSDictionary *> *results = [NSMutableDictionary dictionary];
        
        NSArray<NSString *> *paths = [self launchPlistPaths];
        for (NSUInteger i = 0; i < paths.count; i++) {
            NSString *path = paths[i];
            
            BOOL isLaunchAgent = i == 0 || i == 2 || i == 4;
            BOOL isLaunchDaemon = i == 1 || i == 3 || i == 5;
            BOOL isUserLaunchAgent = i == 4;
            BOOL isUserLaunchDaemon = i == 5;
            
            NSArray<NSString *> *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:path error:nil];
            for (NSString *file in files) {
                if ([file hasSuffix:@".plist"]) {
                    NSString *fullPath = [path stringByAppendingPathComponent:file];
                    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:fullPath];
                    
                    if (plist) {
                        NSString *key = [NSString stringWithFormat:@"program args_%@", plist[@"Label"]];
                        results[key] = @{
                            @"ProgramArguments": plist[@"ProgramArguments"] ?: @[],
                            @"machServices": plist[@"MachServices"] ? [plist[@"MachServices"] allKeys] : @[],
                            @"isLaunchAgent": @(isLaunchAgent),
                            @"isLaunchDaemon": @(isLaunchDaemon),
                            @"isUserLaunchAgent": @(isUserLaunchAgent),
                            @"isUserLaunchDaemon": @(isUserLaunchDaemon)
                        };
                    }
                }
            }
        }
        
        return results;
    }
}

@end
