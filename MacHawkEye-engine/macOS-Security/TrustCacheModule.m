//
//  TrustCacheModule.m
//  macOS-Security
//
//  Created by Carlos Polop on 18/10/23.
//

#import "TrustCacheModule.h"
#import <Foundation/Foundation.h>

@implementation TrustCacheModule
NSMutableDictionary *globalInfoDict;

- (BOOL) isToolInstalled:(NSString *)tool {
    NSTask *task = [[NSTask alloc] init];
    NSString *command = [@"which " stringByAppendingString:tool];
    [task setLaunchPath:@"/bin/zsh"];
    [task setArguments:@[@"-c", command]];
    
    NSPipe *pipe = [NSPipe pipe];
    [task setStandardOutput:pipe];
    
    [task launch];
    [task waitUntilExit];
    
    return [task terminationStatus] == 0;
}

- (NSString *)executeCommand:(NSString *)command {
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:@"/bin/zsh"];
    [task setArguments:@[@"-c", command]];
    
    NSPipe *pipe = [NSPipe pipe];
    [task setStandardOutput:pipe];
    
    [task launch];
    [task waitUntilExit];
    
    NSData *data = [[pipe fileHandleForReading] readDataToEndOfFile];
    NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
    return output;
}

- (NSDictionary *)extractInfo:(NSString *)dataFilePath{
    NSMutableDictionary *infoDict = [NSMutableDictionary dictionary];
    NSString *command = [NSString stringWithFormat:@"trustcache info %@ > /tmp/out_mac_sec.list", dataFilePath];
    [self executeCommand:command];
    
    NSError *error = nil;
    NSString *output = [NSString stringWithContentsOfFile:@"/tmp/out_mac_sec.list" encoding:NSUTF8StringEncoding error:&error];
    if (error) {
        NSLog(@"Error reading file: %@", error.localizedDescription);
        return infoDict;  // or handle the error in some other way
    }
    
    NSArray *lines = [output componentsSeparatedByString:@"\n"];
    for (NSString *line in lines) {
        NSArray *columns = [line componentsSeparatedByString:@" "];
        if (columns.count >= 3) {
            NSString *firstColumn = columns[0];
            firstColumn = [firstColumn lowercaseString];
            NSString *lastColumn = columns.lastObject;
            lastColumn = [[lastColumn stringByReplacingOccurrencesOfString:@"[" withString:@""] stringByReplacingOccurrencesOfString:@"]" withString:@""];
            NSInteger lastColumnInteger = [lastColumn intValue];
            NSNumber *lastColumnNumber = [NSNumber numberWithInteger:lastColumnInteger];
            infoDict[firstColumn] = lastColumnNumber; // Save as int
        }
    }
    
    return infoDict;
}

- (NSArray *)listMatchingFiles:(NSString *)pattern {
    NSString *command = [NSString stringWithFormat:@"ls %@", pattern];
    NSString *output = [self executeCommand:command];
    NSArray *files = [output componentsSeparatedByString:@"\n"];
    // Remove the last object if it's an empty string (which occurs if there's a trailing newline in the output)
    if ([[files lastObject] isEqualToString:@""]) {
        files = [files subarrayWithRange:NSMakeRange(0, files.count - 1)];
    }
    return files;
}


- (void) getTrustCacheInfoWithPattern:(NSString *)pattern withTempFileName:(NSString *)tempFileName{
    NSArray *files = [self listMatchingFiles:pattern];
    for (NSString *file in files) {
        if (file.length > 0) {
            NSString *cpCommand = [NSString stringWithFormat:@"cp %@ /tmp/%@", file, tempFileName];
            [self executeCommand:cpCommand];
            
            NSString *extractImg4Command = [NSString stringWithFormat:@"pyimg4 img4 extract -i /tmp/%@ -p /tmp/%@.im4p", tempFileName, tempFileName];
            [self executeCommand:extractImg4Command];
            
            NSString *extractIm4pCommand = [NSString stringWithFormat:@"pyimg4 im4p extract -i /tmp/%@.im4p -o /tmp/%@.data", tempFileName, tempFileName];
            [self executeCommand:extractIm4pCommand];
            
            NSDictionary *infoDict = [self extractInfo:[NSString stringWithFormat:@"/tmp/%@.data", tempFileName]];
            [globalInfoDict addEntriesFromDictionary:infoDict];
        }
    }
}

- (NSMutableDictionary *) processFiles {
    // Check for required tools
    NSArray *requiredTools = @[@"cp", @"find", @"pyimg4", @"trustcache"];
    for (NSString *tool in requiredTools) {
        if (![self isToolInstalled:tool]) {
            NSLog(@"Error: %@ is not installed.", tool);
            return globalInfoDict;
        }
    }
    
    globalInfoDict = [NSMutableDictionary dictionary];
            
    [self getTrustCacheInfoWithPattern:@"/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4" withTempFileName:@"BaseSystemTrustCache"];
    [self getTrustCacheInfoWithPattern:@"/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4" withTempFileName:@"StaticTrustCache"];
    
    NSString *singleExtractCommand = @"pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data";
    [self executeCommand:singleExtractCommand];
    
    NSDictionary *infoDict = [self extractInfo:@"/tmp/OSLaunchPolicyData.data"];
    [globalInfoDict addEntriesFromDictionary:infoDict];

    return globalInfoDict;
}
@end
