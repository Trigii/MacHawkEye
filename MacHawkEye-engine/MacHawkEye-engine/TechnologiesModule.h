#import <Foundation/Foundation.h>

@interface TechnologiesModule : NSObject

// Method to get information about an executable
- (NSDictionary *)getInfoForExecutable:(NSString *)executable;

@end
