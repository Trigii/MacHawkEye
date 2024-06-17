//
//  TrustCacheModule.h
//  macOS-Security
//
//  Created by Carlos Polop on 18/10/23.
//

#import <Foundation/Foundation.h>

#ifndef TrustCacheModule_h
#define TrustCacheModule_h


#endif /* TrustCacheModule_h */

@interface TrustCacheModule : NSObject

- (BOOL) isToolInstalled:(NSString *)tool;
- (NSString *)executeCommand:(NSString *)command;
- (NSDictionary *)extractInfo:(NSString *)dataFilePath;
- (NSArray *)listMatchingFiles:(NSString *)pattern;
- (void) getTrustCacheInfoWithPattern:(NSString *)pattern withTempFileName:(NSString *)tempFileName;
- (NSMutableDictionary *) processFiles;
@end
