#import "ImportsModule.h"
#import <Foundation/Foundation.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <sys/stat.h>
#include <dlfcn.h>

@implementation ImportsModule

- (NSDictionary *)extractRpathsFromMachoAtPath:(NSString *)path {
    NSMutableDictionary *selectedArchInfo = [NSMutableDictionary dictionary];
    NSData *data = [NSData dataWithContentsOfFile:path];
    const char *bytes = [data bytes];
    NSUInteger dataSize = [data length];
    
    if (dataSize < sizeof(struct fat_header)) return selectedArchInfo;
    
    struct fat_header *fatHeader = (struct fat_header *)bytes;
    if (fatHeader->magic == FAT_MAGIC || fatHeader->magic == FAT_CIGAM) {
        if (dataSize < sizeof(struct fat_header) + sizeof(struct fat_arch)) return selectedArchInfo;
        
        struct fat_arch *arch = (struct fat_arch *)(bytes + sizeof(struct fat_header));
        int architectures = OSSwapBigToHostInt(fatHeader->nfat_arch);
        BOOL foundARM64 = NO;
        for (int i = 0; i < architectures && !foundARM64; i++) {
            NSUInteger offset = OSSwapBigToHostInt(arch->offset);
            NSUInteger size = OSSwapBigToHostInt(arch->size);
            
            if (offset + size > dataSize) break;
            
            // Start storing the first one
            if (i == 0) {
                NSArray *archRpaths = [self extractRpathsForArch:bytes + offset length:size];
                [selectedArchInfo setObject:archRpaths forKey:@"rpaths"];
                [selectedArchInfo setObject:@(offset) forKey:@"offset"];
                [selectedArchInfo setObject:@(size) forKey:@"size"];
            }
            
            NSString *archName = [self architectureNameForType:OSSwapBigToHostInt(arch->cputype)];
            if ([archName isEqualToString:@"ARM64"]) {
                NSArray *archRpaths = [self extractRpathsForArch:bytes + offset length:size];
                [selectedArchInfo setObject:archRpaths forKey:@"rpaths"];
                [selectedArchInfo setObject:@(offset) forKey:@"offset"];
                [selectedArchInfo setObject:@(size) forKey:@"size"];
                foundARM64 = YES;
            }
            arch = (struct fat_arch *)((char *)arch + sizeof(struct fat_arch));
        }
    } else {
        // Handle single architecture binaries
        NSArray *archRpaths = [self extractRpathsForArch:bytes length:dataSize];
        if (archRpaths.count > 0) {
            [selectedArchInfo setObject:archRpaths forKey:@"rpaths"];
            [selectedArchInfo setObject:@(0) forKey:@"offset"]; // start from the beginning
            [selectedArchInfo setObject:@(dataSize) forKey:@"size"]; // entire data
        }
    }
    return selectedArchInfo;
}



- (NSString *)architectureNameForType:(cpu_type_t)type {
    switch (type) {
        case CPU_TYPE_I386:
            return @"i386";
        case CPU_TYPE_X86_64:
            return @"x86_64";
        case CPU_TYPE_ARM:
            return @"ARM";
        case CPU_TYPE_ARM64:
            return @"ARM64";
        // ... Add more architectures as needed
        default:
            return @"Unknown";
    }
}

- (NSArray *)extractRpathsForArch:(const char *)bytes length:(NSUInteger)length {
    NSMutableArray *rpaths = [NSMutableArray array];
    
    if (length < sizeof(struct mach_header)) return rpaths;
    
    struct mach_header *header = (struct mach_header *)bytes;
    
    NSUInteger headerSize = (header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64) ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
    
    struct load_command *cmd = (struct load_command *)(bytes + headerSize);
    
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (length < (char *)cmd - bytes + sizeof(struct load_command)) break;
        
        if (cmd->cmd == LC_RPATH) {
            struct rpath_command *rpathCmd = (struct rpath_command *)cmd;
            
            if (length < (char *)rpathCmd - bytes + sizeof(struct rpath_command) + rpathCmd->path.offset) break;
            
            char *rpath = (char *)rpathCmd + rpathCmd->path.offset;
            [rpaths addObject:[NSString stringWithUTF8String:rpath]];
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    return rpaths;
}


- (NSDictionary *)resolvedDylibPaths:(NSString *)dylibPath originalPath:(NSString *)path rpaths:(NSArray *)rpaths {
    NSMutableArray *resolvedPaths = [NSMutableArray array];
    BOOL isRelative = NO;

    if ([dylibPath containsString:@"@executable_path"] || [dylibPath containsString:@"@loader_path"]) {
        isRelative = YES;
        
        NSString *resolvedPath;
        if ([dylibPath containsString:@"@executable_path"]) {
            resolvedPath = [dylibPath stringByReplacingOccurrencesOfString:@"@executable_path" withString:[path stringByDeletingLastPathComponent]];
        } else {
            resolvedPath = [dylibPath stringByReplacingOccurrencesOfString:@"@loader_path" withString:[path stringByDeletingLastPathComponent]];
        }
        [resolvedPaths addObject:[resolvedPath stringByStandardizingPath]];
        
    } else if ([dylibPath containsString:@"@rpath"]) {
        for (NSString *rpath in rpaths) {
            if ([rpath containsString:@"@rpath"]) {
                // Avoid eternal loops of @rpath inside rpath
                continue;
            }
            
            NSString *potentialPath = [dylibPath stringByReplacingOccurrencesOfString:@"@rpath" withString:rpath];
            
            // RPATH might have also the previous options, resolve them
            NSDictionary *resolvedResult = [self resolvedDylibPaths:potentialPath originalPath:path rpaths:rpaths];
            potentialPath = resolvedResult[@"dylibpaths"][0];
            
            if ([resolvedResult[@"relative"] boolValue]) {
                isRelative = YES;
            }
            
            [resolvedPaths addObject:[potentialPath stringByStandardizingPath]];
        }
        
    } else {
        [resolvedPaths addObject:dylibPath];
    }

    return @{
        @"dylibpaths": resolvedPaths,
        @"relative": @(isRelative)
    };
}


- (BOOL)userIsMemberOfGroup:(gid_t)groupID {
    int ngroups = NGROUPS_MAX;
    gid_t gidset[NGROUPS_MAX];
    getgrouplist(getlogin(), getgid(), gidset, &ngroups);

    for (int i = 0; i < ngroups; i++) {
        if (gidset[i] == groupID) {
            return YES;
        }
    }
    return NO;
}


- (BOOL)userCanDeleteAndRecreateFoldersAtPath:(NSString *)path {
    while (![path isEqualToString:@"/"]) {
        path = [path stringByDeletingLastPathComponent];
        struct stat stats;

        if (lstat([path UTF8String], &stats) != 0) {
            // Error occurred; maybe handle or log
            return NO;
        }

        BOOL isGroupWritable = (stats.st_mode & S_IWGRP) && [self userIsMemberOfGroup:stats.st_gid];
        BOOL isWritable = (stats.st_mode & S_IWOTH) || isGroupWritable || ((stats.st_mode & S_IWUSR) && (stats.st_uid == getuid()));

        if (isWritable) {
            return YES;
        }
    }

    return NO;
}


- (NSDictionary *)getInfoForExecutable:(NSString *)path isRestricted:(BOOL)isRestricted {
    @autoreleasepool {
        NSMutableArray *libraries = [NSMutableArray array];
        
        // Extracting architecture specific info
        NSDictionary *selectedArchInfo = [self extractRpathsFromMachoAtPath:path];
        NSArray *rpaths = selectedArchInfo[@"rpaths"];
        NSUInteger archOffset = [selectedArchInfo[@"offset"] unsignedIntegerValue];
        NSUInteger archSize = [selectedArchInfo[@"size"] unsignedIntegerValue];
        
        NSData *data = [NSData dataWithContentsOfFile:path];
        if (!data || data.length < sizeof(struct mach_header) + archOffset) {
            NSLog(@"Invalid data or too short to be a Mach-O header");
            return @{@"libraries": @[]};
        }
        
        const char *bytes = [data bytes] + archOffset;
        struct mach_header *header = (struct mach_header *)bytes;
        
        if (header->magic != MH_MAGIC && header->magic != MH_MAGIC_64) {
            NSLog(@"Invalid Mach-O magic");
            return @{@"libraries": @[]};
        }
        
        struct load_command *cmd = (struct load_command *)(bytes + sizeof(struct mach_header));
        if (header->magic == MH_MAGIC_64) {
            cmd = (struct load_command *)(bytes + sizeof(struct mach_header_64));
        }
        
        if (data.length < archOffset + sizeof(struct mach_header) + header->ncmds * sizeof(struct load_command)) {
            NSLog(@"Not enough data for all load commands");
            return @{@"libraries": @[]};
        }
        
        for (uint32_t i = 0; i < header->ncmds; i++) {
            if (cmd->cmd == LC_LOAD_DYLIB || cmd->cmd == LC_LOAD_WEAK_DYLIB || cmd->cmd == LC_LOAD_UPWARD_DYLIB) {
                struct dylib_command *dylibCmd = (struct dylib_command *)cmd;
                char *dylibPath = (char *)dylibCmd + dylibCmd->dylib.name.offset;
                
                NSDictionary *pathsInfo = [self resolvedDylibPaths:[NSString stringWithUTF8String:dylibPath] originalPath:path rpaths:rpaths];
                
                NSArray *potentialPaths = pathsInfo[@"dylibpaths"];
                BOOL isRelative = [pathsInfo[@"relative"] boolValue];
                
                for (NSString *resolvedPath in potentialPaths) {
                    struct stat stats;
                    BOOL fileExists = false;
                    BOOL isWritable = false;
                    BOOL isDyld = false;
                    BOOL canCreate = false;
                    if (stat([resolvedPath UTF8String], &stats) == 0) {
                        // If the file exists
                        BOOL isGroupWritable = (stats.st_mode & S_IWGRP) && [self userIsMemberOfGroup:stats.st_gid];
                        isWritable = (stats.st_mode & S_IWOTH) || isGroupWritable || ((stats.st_mode & S_IWUSR) && (stats.st_uid == getuid()));
                        fileExists = true;
                    } else {
                        // If the file doesn't exist, check if known by dylib
                        if (dlopen_preflight([resolvedPath UTF8String])) {
                            fileExists = true;
                            isWritable = false;
                            isDyld = true;
                        } else { // Check if folder writable if no idea where is the file
                            NSString *directory = [resolvedPath stringByDeletingLastPathComponent];
                            isWritable = [[NSFileManager defaultManager] isWritableFileAtPath:directory];
                        }
                        
                    }
                    if (!isDyld) {
                        canCreate = [self userCanDeleteAndRecreateFoldersAtPath:resolvedPath];
                    }
                    
                    NSDictionary *libraryInfo = @{
                        @"path": resolvedPath,
                        @"exists": @(fileExists),
                        @"isWritable": @(isWritable),
                        @"isWeak": @(cmd->cmd == LC_LOAD_WEAK_DYLIB),
                        @"isDyld": @(isDyld),
                        @"canCreate": @(canCreate),
                        @"isHijackable": @(isWritable || canCreate),
                        @"arch": @"ARM64", // Since we're looking specifically for ARM64 or the first architecture
                        @"isRelative": @(isRelative)
                    };
                    [libraries addObject:libraryInfo];
                    
                    if (fileExists) {
                        break;
                    }
                }
            }
            cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
        }
        
        return @{@"libraries": libraries};
    }
    /*
     {
        "libraries": [
            {
             "path": "string",
             "exists": bool,
             "isWritable": bool,
             "isWeak": bool,
             "isDyld": bool,
             "canCreate": bool,
             "isHijackable": bool,
             "arch": bool
            }
        ]
     }
     */
}

@end

