![image](https://github.com/Trigii/MacHawkEye/assets/95245480/5acdb392-da29-47b6-a2e9-44af5790587d)# MacHawkEye

Engine for analyzing binaries on macOS systems to identify potential vulnerabilities

<img width="781" alt="image" src="https://github.com/Trigii/MacHawkEye/assets/17181413/8f0b916a-21e9-41b5-9f84-7cf518853e01">

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
- Enter the path to the generated DB from the engine under the Configuration tab (default location is `/tmp/executables.db`):
![image](https://github.com/Trigii/MacHawkEye/assets/95245480/1e6e01bc-fe73-4482-abda-d399b3f37c57)


- Run prebuilt queries or customize your own queries and run them against the DB:
![image](https://github.com/Trigii/MacHawkEye/assets/95245480/d8d4a810-a07c-4118-bc61-6ed51840a3fe)

