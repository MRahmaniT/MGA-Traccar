# MGA-Traccar
Making a new protocol for Traccar in java. (MgaProtocol)

We added 3 files to "src/main/java/org/traccar/protocol". The files are:
• MgaProtocol
• MgaProtocolDecoder
• MgaProtocolEncoder

- If you want to make any change into receiving data protocol you should edit decoder file.
- If you want to make any change into sending data protocol you should edit encoder file.

We added our port to "src/main/java/org/traccar/config/PortConfigSuffix.java/ " file.
• PORTS.put("mga", 5555);

- If you want to change the port, You just need to change 5555.

We made "tracker-server.jar". You can find it in "target".
• You shoud run "./gradlew assemble" in terminal to make a new "tracker-server.jar".

- If you want to use your protocol, You need to copy all files in target file and paste them in your traccar directory.
