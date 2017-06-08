# FridaAndroidTracer

A runnable jar that generate Javascript hook script to hook Android classes.

## Download

Grab the prebuilt shadow jar (FridaAndroidTracer.jar) inside the repo, or clone the repo, open in IntelliJ IDEA.

## Usage

``` bash
Usage: java -jar FridaAndroidTracer.jar <class names> <output script path> <skip methods> <include private>
	 class names:        classes to be hooked, in csv format, or @filename
	 output script path: output script path
	 skip methods:       methods to be skipped, in csv format, or @filename
	 include private:    optional, "true" to include private methods
```
