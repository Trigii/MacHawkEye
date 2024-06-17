//
//  ProcessesModule.m
//  macOS-Security
//
//  Created by Carlos Polop on 10/10/23.
//

#import "ProcessesModule.h"
#import <Foundation/Foundation.h>
#import <libproc.h>
#import <sys/sysctl.h>


@implementation ProcessModule

- (NSArray<NSString *> *)processRunningExecutablesWithVerbose:(bool)verbose {
    @autoreleasepool {
        int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
        size_t len;
        NSMutableArray<NSString *> *executablePaths = [[NSMutableArray alloc] init];
        
        if (sysctl(mib, 4, NULL, &len, NULL, 0) == -1) {
            perror("sysctl");
            return executablePaths;  // Return empty array in case of error
        }
        
        struct kinfo_proc *procs = malloc(len);
        if (sysctl(mib, 4, procs, &len, NULL, 0) == -1) {
            perror("sysctl");
            free(procs);
            return executablePaths;  // Return empty array in case of error
        }
        
        int nprocs = len / sizeof(struct kinfo_proc);
        for (int i = 0; i < nprocs; i++) {
            pid_t pid = procs[i].kp_proc.p_pid;
            char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
            if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
                NSString *executablePath = [NSString stringWithUTF8String:pathbuf];
                if (![executablePaths containsObject:executablePath]) {
                    [executablePaths addObject:executablePath];  // Add the executable path to the array
                    
                    if (verbose) {
                        NSLog(@"Found executable: %@", executablePath);
                    }
                }
            }
        }
        
        free(procs);
        return [executablePaths copy];  // Return a non-mutable copy of the array
    }
}

@end
