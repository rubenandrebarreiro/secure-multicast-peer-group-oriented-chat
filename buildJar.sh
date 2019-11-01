#!/bin/bash
mvn clean package assembly:single
mv target/*jar-with-dependencies*.jar ./SecureMchatClient.jar
