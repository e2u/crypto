#!/bin/bash
cps="./:./commons-codec-1.9.jar"
javac -cp $cps AES.java
java -cp $cps AES
rm AES.class
