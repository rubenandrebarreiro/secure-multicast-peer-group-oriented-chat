#!/bin/bash
mvn clean package assembly:single
mkdir -p SecureMChatClient-Application-Phase1
mv target/*jar-with-dependencies*.jar ./SecureMChatClient-Application-Phase1/SecureMchatClient.jar
jarsigner -keystore signKeystore SecureMChatClient-Application-Phase1/*.jar sign
