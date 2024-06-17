//
//  HandlersModule.m
//  macOS-Security
//
//  Created by Carlos Polop on 21/10/23.
//

#import <Foundation/Foundation.h>
#import <CoreServices/CoreServices.h>
#import <AppKit/AppKit.h>
#import "HandlersModule.h"


extern OSStatus _LSCopySchemesAndHandlerURLs(NSArray * __nullable * __nonnull, NSMutableArray * __nullable * __nonnull);
extern OSStatus _LSCopyAllApplicationURLs(NSMutableArray * __nullable * __nonnull);
extern NSArray * _UTCopyDeclaredTypeIdentifiers(void);


@implementation HandlersModule : NSObject

+ (NSDictionary<NSString *, NSString *> *)getAllUTIs {
    CFArrayRef UTIsRef = (__bridge CFArrayRef)_UTCopyDeclaredTypeIdentifiers();
    NSArray<NSString *> *UTIs = (__bridge_transfer NSArray *)UTIsRef;
    NSMutableArray<NSString *> *filteredUTIs = [NSMutableArray array];
    NSMutableArray<NSString *> *handlers = [NSMutableArray array];
    
    for (NSString *UTI in UTIs) {
        if (UTTypeConformsTo((__bridge CFStringRef)UTI, CFSTR("public.item")) ||
            UTTypeConformsTo((__bridge CFStringRef)UTI, CFSTR("public.content"))) {
            NSString *handler = [self copyDefaultHandler:UTI inRoles:kLSRolesViewer | kLSRolesEditor asPath:YES];
            if (handler) {
                [filteredUTIs addObject:UTI];
                [handlers addObject:handler];
            }
        }
    }
    
    NSMutableDictionary<NSString *, NSString *> *result = [NSMutableDictionary dictionary];
    [filteredUTIs enumerateObjectsUsingBlock:^(NSString * _Nonnull UTI, NSUInteger idx, BOOL * _Nonnull stop) {
        result[UTI] = handlers[idx];
    }];
    
    return [NSDictionary dictionaryWithDictionary:result];
}


+ (nullable NSString *)copyDefaultHandler:(NSString *)inUTI inRoles:(LSRolesMask)inRoles asPath:(BOOL)asPath {
    CFStringRef handlerIDRef = LSCopyDefaultRoleHandlerForContentType((__bridge CFStringRef)inUTI, inRoles);
    if (handlerIDRef != NULL) {
        NSString *handlerID = (__bridge_transfer NSString *)handlerIDRef;
        if (asPath) {
            NSURL *handlerURL = [[NSWorkspace sharedWorkspace] URLForApplicationWithBundleIdentifier:handlerID];
            return handlerURL.path;
        } else {
            return handlerID;
        }
    }
    return nil;
}

+ (NSArray<NSString *> *)convertAppURLsToPaths:(NSArray<NSURL *> *)inArray {
    NSMutableArray<NSString *> *outputArray = [NSMutableArray array];
    for (NSURL *app in inArray) {
        [outputArray addObject:app.path];
    }
    return outputArray.count > 0 ? [outputArray copy] : nil;
}

+ (nullable NSDictionary<NSString *, NSString *> *)getAllSchemes {
    NSArray *schemesArray = nil;
    NSMutableArray *appsArray = nil;
    // Assuming LSCopySchemesAndHandlerURLs is a function that fills schemesArray and appsArray
    OSStatus status = _LSCopySchemesAndHandlerURLs(&schemesArray, &appsArray);
    if (status == noErr) {
        NSArray<NSString *> *pathsArray = [self convertAppURLsToPaths:appsArray];
        if (pathsArray) {
            NSMutableDictionary<NSString *, NSString *> *schemesHandlers = [NSMutableDictionary dictionary];
            for (NSUInteger i = 0; i < schemesArray.count && i < pathsArray.count; i++) {
                schemesHandlers[schemesArray[i]] = pathsArray[i];
            }
            return [schemesHandlers copy];
        }
    }
    return nil;
}

@end
