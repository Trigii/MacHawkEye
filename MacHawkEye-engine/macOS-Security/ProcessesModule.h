//
//  ProcessesModule.h
//  macOS-Security
//
//  Created by Carlos Polop on 10/10/23.
//

#import <Foundation/Foundation.h>


#ifndef ProcessesModule_h
#define ProcessesModule_h


#endif /* ProcessesModule_h */

@interface ProcessModule : NSObject

- (NSArray<NSString *> *)processRunningExecutablesWithVerbose:(bool)verbose;

@end
