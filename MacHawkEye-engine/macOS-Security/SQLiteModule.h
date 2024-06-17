#import <Foundation/Foundation.h>
#import <sqlite3.h>

@interface SQLiteModule : NSObject

- (instancetype)initWithDatabasePath:(NSString *)path;
- (void)storeScriptInfo:(NSString*)script_path;
- (void)storeInfo:(NSDictionary *)info forExecutable:(NSString *)executable withAllUTIs:(NSDictionary *)allUTIs withAllSchemes:(NSDictionary *)allSchemes;
- (NSString *)findPathUntilFirstFolderWithExtension:(NSString *)absPath;
@end
