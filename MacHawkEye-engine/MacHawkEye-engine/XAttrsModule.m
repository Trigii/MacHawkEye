#import "XAttrsModule.h"
#import <sys/xattr.h>


@implementation XAttrsModule

- (NSDictionary *)getInfoForExecutable:(NSString *)executablePath {
    @autoreleasepool {
        NSMutableDictionary *info = [NSMutableDictionary dictionary];
        const char *filePath = [executablePath fileSystemRepresentation];
        ssize_t nameLength = listxattr(filePath, NULL, 0, 0);
        
        if (nameLength > 0) {
            char *nameList = (char *)malloc(nameLength);
            listxattr(filePath, nameList, nameLength, 0);
            
            NSMutableArray *extendedAttributes = [NSMutableArray array];
            char *currentName = nameList;
            while (currentName < (nameList + nameLength)) {
                [extendedAttributes addObject:[NSString stringWithUTF8String:currentName]];
                currentName += strlen(currentName) + 1;  // Move to the next name
            }
            
            NSString *joinedXAttrs = [extendedAttributes componentsJoinedByString:@", "];
            [info setObject:joinedXAttrs forKey:@"Extended attributes"];
            
            free(nameList);
        }
        
        return info;
    }
    
    /*
     {
        "Extended attributes": "string"
     }
     */
}

@end

