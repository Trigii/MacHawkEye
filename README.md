# MacHawkEye

Engine for analyzing binaries on macOS systems to identify potential vulnerabilities


## Run the engine

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
./MacHawkEye-engine  --user-tcc-db /tmp/TCC_user.db --system-tcc-db /tmp/TCC_system.db --auth-db /tmp/auth.db -o /tmp/executables.db

```

## Run the GUI

### Run from Xcode
- Open the GUI project on Xcode and click the Run button (it will build and run the GUI automatically)

### Run from Terminal

- Build the project on Xcode (`Product -> Build`)

- Navigate to the build (location is under `File -> Project Settings` on Xcode):
```bash
cd $HOME/Library/Developer/Xcode/DerivedData/MacHawkEye-gui-{RANDOM}
```

- Execute the GUI:
```bash
./MacHawkEye-gui.app/Contents/MacOS/MacHawkEye-gui
```
### Usage
- Enter the path to the generated DB from the engine under the Configuration tab (default is `/tmp/executables.db`)
- Run prebuilt queries or customize your own queries and run them against the DB