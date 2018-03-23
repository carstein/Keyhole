BinaryNinja Keyhole
====================
Plugin for [Binary Ninja](https://binary.ninja/) platform

## General
This plugin iterates over all recognized functions in a binary and present short report about findings.
Such findings might help reverser to determine _interesting_ functions and where to start looking.

## Features
### Overview
In main view user is presented with following information about all functions:
 - number of instructions
 - number of basic blocks
 - number of function calls
 - number of times given function is being called
 
 ![Main View](https://i.imgur.com/4z1B2jF.png)

### Function Details
In side pane user is presented with detailed list of functions given function call and with all the cross references to a given function.

![Function Pane](https://i.imgur.com/Acvqktp.png)

### Binary fingerprint
Ueer is presented with an image draw using hilberts curve that displays type of instructions in a given function. Such view might help reverser to spot certain characteristics like dense clusters of arthemetic or data operations.

![Fingerprint](https://i.imgur.com/nMxP8AP.png)

## TODO
- [x] Basic report
- [x] Report about given function
- [x] Basic binary fingerprint
- [ ] More instructions recognized by binary fingerprint
- [ ] Enchance basic report by adding additional characteristics
