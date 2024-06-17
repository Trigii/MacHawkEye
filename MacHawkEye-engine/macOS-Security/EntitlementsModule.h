#import <Foundation/Foundation.h>

@interface EntitlementsModule : NSObject

// Method to get entitlements information for a given executable
- (NSDictionary *)getInfoForExecutable:(NSString *)executable
                        withUsersTCCdb:(NSString *)usersTCCdb
                       withSystemTCCdb:(NSString *)systemTCCdb
                            withAuthDB:(NSString *)authDBpath;

- (NSString *)getCertificateDetailsForExecutable:(NSString *)executable;
- (BOOL)isIdentifierInSandboxContainer:(NSString *)exec_id;
- (BOOL)isLoadLibraryRestrictedByFlags:(NSInteger)flags;
- (NSString *)rulesForBundleID:(NSString *)bundleID withAuthDB:(NSString *)authDBpath;
- (NSString *)ruleValueForIdentifier:(NSString *)identifier;
- (BOOL)hasRestrictSegmentInMachO:(int)fd;
- (BOOL)hasRestrictHeaderSection:(NSString *)path;
- (BOOL)isAppleIdentifier:(NSString *)identifier;
- (NSArray *)getStringFlagsFromInteger:(NSInteger)flags;

- (NSString *)getAllTCCPermissionsForBundle:(NSString *)bundleID
                             withUsersTCCdb:(NSString *)usersTCCdb
                            withSystemTCCdb:(NSString *)systemTCCdb;

@end
