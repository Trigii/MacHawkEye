#import <Foundation/Foundation.h>

@interface SUGIDModule : NSObject

// Method to check if the executable is SUID
- (BOOL)isSUID:(NSString *)executablePath;

// Method to check if the executable is SGID
- (BOOL)isSGID:(NSString *)executablePath;

// Method to get information for the executable
- (NSDictionary *)getInfoForExecutable:(NSString *)executablePath;

@end
