//
//  DaemonsModule.m
//  macOS-Security
//
//  Created by Carlos Polop on 17/10/23.
//

#import "DaemonsModule.h"
#import <Foundation/Foundation.h>

#import <Foundation/Foundation.h>


@implementation DaemonsModule

- (NSArray<NSDictionary *> *)discoverDaemonsWithXPCServices {
    @autoreleasepool {
        NSMutableArray<NSDictionary *> *daemonInfoArray = [NSMutableArray array];
        
        NSArray *directories = @[@"/Library/LaunchDaemons", @"/System/Library/LaunchDaemons", @"/Library/LaunchAgents", @"/System/Library/LaunchAgents"];
        
        for (NSString *directory in directories) {
            NSError *error = nil;
            NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:directory error:&error];
            
            if (error) {
                NSLog(@"Error reading directory: %@", error);
                continue;
            }
            
            for (NSString *file in files) {
                if (![file hasSuffix:@".plist"]) continue;  // Skip non-plist files
                
                NSString *filePath = [directory stringByAppendingPathComponent:file];
                NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:filePath];
                
                
                NSDictionary *xpcServices = plist[@"MachServices"];  // Assume XPC services are listed under this key
                NSString *binaryPath = plist[@"Program"];
                if ([binaryPath length] == 0){
                    binaryPath = plist[@"ProgramArguments"][0];
                }
                
                if (xpcServices == nil) {
                    xpcServices = [NSDictionary dictionary];
                }
                if ([binaryPath length] > 0) {
                    NSDictionary *daemonInfo = @{@"binaryPath": binaryPath,
                                                 @"machServices": xpcServices};
                    [daemonInfoArray addObject:daemonInfo];
                }
                else {
                    NSLog(@"Daemon program not found!");
                }
            }
        }
        
        NSArray<NSDictionary *> *combinedResults = [self combineDaemonInfo:daemonInfoArray];
        
        return combinedResults;
    }
}

- (NSArray<NSDictionary *> *)combineDaemonInfo:(NSArray<NSDictionary *> *)daemonInfoArray {
    NSMutableDictionary<NSString *, NSMutableSet<NSString *> *> *combinedInfo = [NSMutableDictionary dictionary];
    
    // Step 2: Iterate through each daemonInfo dictionary
    for (NSDictionary *daemonInfo in daemonInfoArray) {
        NSString *binaryPath = daemonInfo[@"binaryPath"];
        NSArray<NSString *> *xpcServices = [daemonInfo[@"machServices"] allKeys];
        
        // Step 3: Check if binaryPath is already a key in combinedInfo
        NSMutableSet *existingServices = combinedInfo[binaryPath];
        if (existingServices) {
            // existingServices is already a NSMutableSet, so you can just add the new xpcServices to it directly
            [existingServices addObjectsFromArray:xpcServices];
        } else {
            // If it isn't, create a new set and add a new entry to combinedInfo
            NSMutableSet *newServices = [NSMutableSet setWithArray:xpcServices];
            combinedInfo[binaryPath] = newServices;
        }
    }
    
    // Step 4: Convert the NSMutableSets to NSArrays and create the final results array
    NSMutableArray<NSDictionary *> *finalResults = [NSMutableArray array];
    for (NSString *binaryPath in combinedInfo) {
        NSArray *xpcServices = [combinedInfo[binaryPath] allObjects];
        NSString *xpcServicesString = [xpcServices componentsJoinedByString:@", "];
        NSDictionary *result = @{@"binaryPath": binaryPath, @"machServices": xpcServicesString};
        [finalResults addObject:result];
    }
    
    return [finalResults copy];
}

@end
