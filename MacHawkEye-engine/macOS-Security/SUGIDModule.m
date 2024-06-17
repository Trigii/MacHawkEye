#import "SUGIDModule.h"
#include <sys/stat.h>

@implementation SUGIDModule

- (BOOL)isSUID:(NSString *)executablePath {
    struct stat fileStat;
    if(stat([executablePath UTF8String], &fileStat) < 0)    
        return NO;
    return fileStat.st_mode & S_ISUID;
}

- (BOOL)isSGID:(NSString *)executablePath {
    struct stat fileStat;
    if(stat([executablePath UTF8String], &fileStat) < 0)    
        return NO;
    return fileStat.st_mode & S_ISGID;
}

- (NSDictionary *)getInfoForExecutable:(NSString *)executablePath {
    BOOL isSUID = [self isSUID:executablePath];
    BOOL isSGID = [self isSGID:executablePath];
    
    // Create a dictionary with the information
    NSDictionary *info = @{
        @"isSUID": @(isSUID),
        @"isSGID": @(isSGID)
    };
    
    return info;
    
    /*
     {
        "isSUID": bool,
        "isSGID": bool
     }
     */
}

@end
