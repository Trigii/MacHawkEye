#import "TechnologiesModule.h"
#include <mach-o/loader.h>
#include <mach/machine.h>
#include <mach-o/fat.h>


@implementation TechnologiesModule

- (NSDictionary *)getInfoForExecutable:(NSString *)executablePath {
    @autoreleasepool {
        NSMutableDictionary *info = [NSMutableDictionary dictionary];
        
        // Get the file extension
        NSString *extension = [executablePath pathExtension];
        [info setObject:extension forKey:@"extension"];
        
        // Map extension to probable type
        NSString *probableType = @"Unknown";
        if ([extension isEqualToString:@"py"]) {
            probableType = @"Python Script";
        } else if ([extension isEqualToString:@"rb"]) {
            probableType = @"Ruby Script";
        } else if ([extension isEqualToString:@"pl"] || [extension isEqualToString:@"pm"]) {
            probableType = @"Perl Script";
        } else if ([extension isEqualToString:@"php"]) {
            probableType = @"PHP Script";
        } else if ([extension isEqualToString:@"js"]) {
            probableType = @"JavaScript";
        } else if ([extension isEqualToString:@"sh"]) {
            probableType = @"Shell Script";
        }
        
        // Read the beginning of the file for "shebang" to confirm type
        NSData *data = [NSData dataWithContentsOfFile:executablePath options:NSDataReadingMappedIfSafe error:nil];
        if (data.length > 23) {
            NSString *startOfFile = [[NSString alloc] initWithData:[data subdataWithRange:NSMakeRange(0, 23)] encoding:NSUTF8StringEncoding];
            
            if ([startOfFile hasPrefix:@"#!/usr/bin/env python"] || [startOfFile hasPrefix:@"#!/usr/bin/python"]) {
                probableType = @"Python Script";
            } else if ([startOfFile hasPrefix:@"#!/usr/bin/env ruby"] || [startOfFile hasPrefix:@"#!/usr/bin/ruby"]) {
                probableType = @"Ruby Script";
            } else if ([startOfFile hasPrefix:@"#!/usr/bin/env perl"] || [startOfFile hasPrefix:@"#!/usr/bin/perl"]) {
                probableType = @"Perl Script";
            } else if ([startOfFile hasPrefix:@"#!/usr/bin/env php"] || [startOfFile hasPrefix:@"#!/usr/bin/php"]) {
                probableType = @"PHP Script";
            } else if ([startOfFile hasPrefix:@"#!/bin/sh"]) {
                probableType = @"Shell Script";
            } else if ([startOfFile hasPrefix:@"#!/bin/bash"]) {
                probableType = @"Shell Script";
            } else if ([startOfFile hasPrefix:@"#!/bin/zsh"]) {
                probableType = @"Shell Script";
            }
        }
        
        if (data.length > 4) {
            uint32_t *magicBytes = (uint32_t *)[data bytes];
            
            if (*magicBytes == MH_MAGIC || *magicBytes == MH_MAGIC_64 || *magicBytes == MH_CIGAM || *magicBytes == MH_CIGAM_64) {
                probableType = @"macOS Binary";
                
                struct mach_header *header = (struct mach_header *)[data bytes];
                if (header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64) {
                    [info setObject:@"x86_64" forKey:@"Architectures"];
                } else if (header->magic == MH_MAGIC || header->magic == MH_CIGAM) {
                    [info setObject:@"i386" forKey:@"Architectures"];
                }
                
            } else if (*magicBytes == FAT_MAGIC || *magicBytes == FAT_CIGAM) {
                probableType = @"macOS Binary";
                
                struct fat_header *fatHeader = (struct fat_header *)[data bytes];
                NSMutableArray *architectures = [NSMutableArray array];
                
                // Loop through each architecture in the fat header
                struct fat_arch *arch = (struct fat_arch *)(fatHeader + 1);
                for (uint32_t i = 0; i < OSSwapBigToHostInt32(fatHeader->nfat_arch); i++, arch++) {
                    if (OSSwapBigToHostInt32(arch->cputype) == CPU_TYPE_X86_64) {
                        [architectures addObject:@"x86_64"];
                    } else if (OSSwapBigToHostInt32(arch->cputype) == CPU_TYPE_I386) {
                        [architectures addObject:@"i386"];
                    } else if (OSSwapBigToHostInt32(arch->cputype) == CPU_TYPE_ARM64) {
                        [architectures addObject:@"arm64"];
                    }
                }
                
                NSString *joinedArchs = [architectures componentsJoinedByString:@", "];
                [info setObject:joinedArchs forKey:@"Architectures"];
                
            } else if (*magicBytes == 0x7f454c46) {
                probableType = @"Linux Binary";
            }
        }
        
        [info setObject:probableType forKey:@"ExecutableType"];
        
        return info;
    }
    /*
     {
        "ExecutableType": "String",
        "Architectures": "String"
     }
     */
}



@end
