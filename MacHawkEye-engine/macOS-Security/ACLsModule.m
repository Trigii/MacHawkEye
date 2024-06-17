#import "ACLsModule.h"
#import <sys/acl.h>


@implementation ACLsModule

- (NSDictionary *)getInfoForExecutable:(NSString *)executablePath {
    const char *cPath = [executablePath fileSystemRepresentation];
    NSMutableDictionary *info = [NSMutableDictionary dictionary];

    // Get the ACL from the file
    acl_t acl = acl_get_file(cPath, ACL_TYPE_EXTENDED);
    if (acl != NULL) {
        // Convert the ACL to text
        ssize_t len;
        char *aclText = acl_to_text(acl, &len);
        if (aclText != NULL) {
            // Convert the C string to NSString
            NSString *aclString = [NSString stringWithUTF8String:aclText];
            [info setObject:aclString forKey:@"acls"];
            
            // Free the text
            acl_free(aclText);
        }
        // Free the ACL
        acl_free(acl);
    }

    return info;
    /*
     {
        "acls": "string"
     }
     */
}

@end


