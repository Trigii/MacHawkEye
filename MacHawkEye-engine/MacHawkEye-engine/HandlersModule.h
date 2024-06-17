//
//  HandlersModule.h
//  macOS-Security
//
//  Created by Carlos Polop on 21/10/23.
//

#import <Foundation/Foundation.h>


#ifndef HandlersModule_h
#define HandlersModule_h


#endif /* HandlersModule_h */

@interface HandlersModule : NSObject

+ (nullable NSDictionary *)getAllUTIs;
+ (nullable NSString *)copyDefaultHandler:(nonnull NSString *)inUTI inRoles:(LSRolesMask)inRoles asPath:(BOOL)asPath;
+ (nullable NSArray<NSString *> *)convertAppURLsToPaths:(nonnull NSArray<NSURL *> *)inArray;
+ (nullable NSDictionary<NSString *, NSString *> *)getAllSchemes;
@end
