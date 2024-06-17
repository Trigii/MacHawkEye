# MacHawkEye

Engine for analyzing binaries on macOS systems to identify potential vulnerabilities


## Run

- Create a copy of `$HOME/Library/Application Support/com.apple.TCC/TCC.db`. From Terminal with FDA permissions: 

```bash
cp "$HOME/Library/Application Support/com.apple.TCC/TCC.db" /tmp/TCC_user.db && sudo chmod +r /tmp/TCC_user.db
```

- Create a copy of `/Library/Application Support/com.apple.TCC/TCC.db`. From Terminal with FDA permissions:

```bash
cp "/Library/Application Support/com.apple.TCC/TCC.db" /tmp/TCC_system.db && chmod +r /tmp/TCC_system.db
```

- Create a copy of `/var/db/auth.db`. From Terminal with FDA permissions:

```bash
sudo cp "/var/db/auth.db" /tmp/auth.db && sudo chmod +r /tmp/auth.db
```

Run:

```bash
./macOS-Security  --user-tcc-db /tmp/TCC_user.db --system-tcc-db /tmp/TCC_system.db --auth-db /tmp/auth.db -o /tmp/executables.db

```

## Queries

### Privileged binaries

- Get executables with high privileges

```sql
SELECT path, privileged, privilegedReasons FROM executables WHERE privileged="High";
```

- Get executables with medium privileges

```sql
SELECT path, privileged, privilegedReasons FROM executables WHERE privileged="Medium";
```

### Injectable privileged binaries

- Get executables with high privileges and injectable level medium or high

```sql
SELECT path, privileged, privilegedReasons, injectable, injectableReasons FROM executables WHERE privileged="High" AND (injectable == "Medium" OR injectable == "High");
```

- Get executables with medium privileges and injectable level high

```sql
SELECT path, privileged, privilegedReasons, injectable, injectableReasons FROM executables WHERE privileged="Medium" AND injectable == "High";
```

### Specific Injection queries

#### Electron Apps

- Use Electron code injection techniques to inject code into the app

```sql
SELECT path, privileged, privilegedReasons, injectable, injectableReasons FROM executables WHERE injectableReasons LIKE "%isElectron%";
```

- Get Electron app bundles

```sql
SELECT bundle_path FROM bundles WHERE isElectron;
```

#### Get DYLD_INSERT_LIBRARIES without library validation

- Use the env variable `DYLD_INSERT_LIBRARIES` to load arbitrary libraries into the binary

```sql
SELECT e.path, e.privileged, e.privilegedReasons
FROM executables e
WHERE e.noLibVal = 1 AND e.allowDyldEnv = 1;
```

#### Macho Task Port

- Get binaries with the entitlement `com.apple.system-task-ports` to read/write memory of other processes:

```sql
SELECT path FROM executables where entitlements like "%com.apple.system-task-ports%";
```

- Get binaries with the entitlement `com.apple.security.get-task-allow` that allows other processes to get the task port of the binary:

```sql
SELECT path FROM executables where entitlements like "%com.apple.security.get-task-allow%";
```

#### Get Hijackable (Dyld hijack & Dlopen hijack) binaries:

- Perform a Dyld hijack on the binary by creating/overwritting the library
- These are potentially unexploitable unless you can modify apps (`kTCCServiceSystemPolicyAppBundles`)

```sql
SELECT e.path, e.privileged, e.privilegedReasons, l.path
FROM executables e
JOIN executable_libraries el ON e.path = el.executable_path
JOIN libraries l ON el.library_path = l.path
WHERE l.isHijackable = 1 AND e.noLibVal = 1;
```

#### Get other potential Dlopen hijackable binaries (potentially root needed to create the file):

- Perform a Dlopen hijack on the binary by creating/overwritting the library in the DLopen searched place
- These are potentially unexploitable unless you can modify apps (`kTCCServiceSystemPolicyAppBundles`)

```sql
SELECT e.path, e.privileged, e.privilegedReasons, l.path
FROM executables e
JOIN executable_libraries el ON e.path = el.executable_path
JOIN libraries l ON el.library_path = l.path
WHERE l.isDyld = 0 AND l.pathExists = 0 AND l.isHijackable = 0 AND e.noLibVal = 1;
```

#### Check non apple apps with high/medium privileges, no library validation, and with relative imports to abuse them

- Move the application to a writable folder and hijack the relative library

```sql
SELECT e.path, e.privileged, e.privilegedReasons, l.path
FROM executables e
JOIN executable_libraries el ON e.path = el.executable_path
JOIN libraries l ON el.library_path = l.path
WHERE e.noLibVal=1 AND (e.privileged="High" OR e.privileged="Medium") AND NOT e.isAppleBin AND l.isRelative AND NOT e.privilegedReasons="isDaemon";
```

### Executable Queries

- Unrestricted executables (no hardeneded runtime, lib validation or restrction flag) and no restricted segments (no __RESTRICT/__restrict):

```sql
SELECT path FROM executables where isRestricted=0;
```

- Unrestricted non Apple executables:

```sql
SELECT path FROM executables where isRestricted=0 and isAppleBin=0;
```

- Executables with sandbox exceptions:

```sql
SELECT path FROM executables WHERE sandboxDefinition != "";
```

- Executables with ACLs:

```sql
SELECT path FROM executables WHERE acls != "";
```

- Executables with XPC rules:

```sql
SELECT path, xpcRules FROM executables WHERE xpcRules != "{}";
```

- Executables with TCC perms:

```sql
SELECT path, tccPerms FROM executables WHERE tccPerms != "";
```

- Executables with macServices:

```sql
SELECT path, machServices FROM executables WHERE machServices != "";
```

### Bundles Queries

- Bundles with exposed schemes:

```sql
SELECT bundle_path, schemes FROM bundles WHERE schemes != "";
```

- Bundles with exposed utis:

```sql
SELECT bundle_path, utis FROM bundles WHERE utis != "";
```