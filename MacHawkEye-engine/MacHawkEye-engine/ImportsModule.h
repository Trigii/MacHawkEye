#import <Foundation/Foundation.h>

@interface ImportsModule : NSObject

// Method to get the imports of the executable
- (NSDictionary *)getInfoForExecutable:(NSString *)path isRestricted:(BOOL)isRestricted;

@end
