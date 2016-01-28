FDNS
===

This is just an experiment to build a fast and simple alternative to bind & learn ho to go.
Load's a simple configuration file (json) and serves the records.. 

Works for now:
* Configuration handling (most of it)
* A and MX records, more will be implemented soon


*DO NOT USE IN PRODUCTION*

*NOT FUNCTIONAL ATM*

_TODO's:_
* Handle requests correctly
* Implement caching and/or db..
* Implement missing configuration options
* Write some proper comments, remove "magick" things..
* Review the code
* Test the code (Code coverage, speed & stuff..)

Thanks to:
* https://github.com/miekg/dns 
* https://github.com/skynetservices/skydns/blob/master/msg/service.go 
