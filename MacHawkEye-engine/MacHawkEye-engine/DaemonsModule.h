//
//  DaemonsModule.h
//  macOS-Security
//
//  Created by Carlos Polop on 17/10/23.
//

#import <Foundation/Foundation.h>


#ifndef DaemonsModule_h
#define DaemonsModule_h


#endif /* DaemonsModule_h */

@interface DaemonsModule : NSObject

- (NSArray<NSDictionary *> *)discoverDaemonsWithXPCServices;
- (NSArray<NSDictionary *> *)combineDaemonInfo:(NSArray<NSDictionary *> *)daemonInfoArray;

@end
