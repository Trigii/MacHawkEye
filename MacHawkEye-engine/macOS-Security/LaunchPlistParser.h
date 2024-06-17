#import <Foundation/Foundation.h>

@interface LaunchPlistParser : NSObject

- (NSDictionary<NSString *, NSDictionary *> *)parseAllLaunchPlists;

@end
