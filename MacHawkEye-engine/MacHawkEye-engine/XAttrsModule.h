#import <Foundation/Foundation.h>

@interface XAttrsModule : NSObject

// This method will return the Access Control List (ACL) for the given executable file.
// It will return a dictionary with the ACL information.
- (NSDictionary *)getInfoForExecutable:(NSString *)executablePath;

@end

