package com.github.piasy.frida_android_tracer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Parameter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.stream.Stream;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 * Created by Piasy on 02/06/2017.
 */
public class FridaAndroidTracer {
    private static final String INDENT = "    ";

    private final ClassLoader mClassLoader;
    private final Random mRandom = new Random(System.currentTimeMillis());
    private final Map<String, String> mArrayNames = new HashMap<>();
    private final Set<String> mSkipMethods = new HashSet<>();

    public FridaAndroidTracer(String[] jars, String[] skipMethods) {
        mArrayNames.put("[Z", "boolean[]");
        mArrayNames.put("[B", "byte[]");
        mArrayNames.put("[C", "char[]");
        mArrayNames.put("[S", "short[]");
        mArrayNames.put("[I", "int[]");
        mArrayNames.put("[J", "long[]");
        mArrayNames.put("[F", "float[]");
        mArrayNames.put("[D", "double[]");

        mSkipMethods.addAll(
                Arrays.asList("finalize", "wait", "equals", "toString", "hashCode", "getClass",
                        "notify", "notifyAll"));
        mSkipMethods.addAll(Arrays.asList(skipMethods));

        mClassLoader = loadJars(jars);
    }

    public static void main(String[] argv) {
        CommandLineParser parser = new DefaultParser();
        Options options = new Options();
        options.addRequiredOption("j", "jars", true, "jar files to be included")
                .addRequiredOption("c", "classes", true, "classes to be hooked")
                .addRequiredOption("o", "output", true, "output script path")
                .addOption("s", "skip", true, "methods to be skipped")
                .addOption("p", "include-private", false, "include private methods")
                .addOption("a", "expand-array", false, "expand array values");

        try {
            CommandLine cmd = parser.parse(options, argv);

            String[] jarFiles = getInputs(cmd.getOptionValue("j"));
            String[] classes = getInputs(cmd.getOptionValue("c"));
            String outputFileName = cmd.getOptionValue("o");

            String[] skipMethods;
            if (cmd.hasOption("s")) {
                skipMethods = getInputs(cmd.getOptionValue("s"));
            } else {
                skipMethods = new String[0];
            }

            boolean includePrivate = cmd.hasOption("p");
            boolean expandArrayValue = cmd.hasOption("a");

            FridaAndroidTracer tracer = new FridaAndroidTracer(jarFiles, skipMethods);
            tracer.generate(classes, includePrivate, expandArrayValue, outputFileName);
        } catch (ParseException e) {
            System.err.println("parse error: " + e.getMessage());
            new HelpFormatter().printHelp("java -jar FridaAndroidTracer.jar", options);
        }
    }

    private static String[] getInputs(String input) {
        if (input.startsWith("@")) {
            try {
                BufferedReader reader = new BufferedReader(new FileReader(input.substring(1)));
                String data = reader.readLine();
                return data.split(",");
            } catch (IOException e) {
                System.out.println("read inputs fail from: " + input);
                e.printStackTrace();
                return new String[0];
            }
        } else {
            return input.split(",");
        }
    }

    public void generate(String[] classes, boolean includePrivate, boolean expandArrayValue,
            String output) {
        if (mClassLoader == null) {
            System.err.println("Load jar files fail!");
            System.exit(1);
        }

        StringBuilder script = new StringBuilder();

        script.append("////////// auto-gen hook script\n\n")
                .append(printArgs())
                .append(expandArrays())
                .append("Java.perform(function () {\n");

        for (String className : classes) {
            Class clazz = findClass(mClassLoader, className);

            if (clazz == null) {
                System.err.println("Class not found: " + className);
                continue;
            }

            script.append(hookClass(clazz, includePrivate, expandArrayValue, 1));
        }

        script.append(INDENT)
                .append("send(\"Hook started!\");\n")
                .append("});\n");

        saveScript(output, script.toString());

        System.out.println("Generate success!");
    }

    private ClassLoader loadJars(String[] jarFiles) {
        URL[] urls = Stream.of(jarFiles)
                .map(name -> {
                    try {
                        return new File(name).toURI().toURL();
                    } catch (MalformedURLException e) {
                        System.out.println("Fail to load jar file: " + name);
                        e.printStackTrace();
                        return null;
                    }
                })
                .toArray(URL[]::new);
        return URLClassLoader.newInstance(urls, ClassLoader.getSystemClassLoader());
    }

    private Class findClass(ClassLoader classLoader, String className) {
        try {
            return classLoader.loadClass(className);
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    private String hookClass(Class clazz, boolean includePrivate, boolean expandArrayValue,
            int indents) {
        StringWriter writer = new StringWriter();
        PrintWriter printer = new PrintWriter(writer);

        printIndents(printer, indents);
        printer.println("////////// auto-gen hook script for class: " + clazz.getName());

        printIndents(printer, indents);
        printer.println(String.format("var %s = Java.use(\"%s\");",
                clazz.getSimpleName(), clazz.getName()));

        printer.println();

        for (Constructor constructor : clazz.getConstructors()) {
            hookMethod(printer, clazz, "$init", constructor.getParameters(), clazz.getSimpleName(),
                    expandArrayValue, indents);
        }

        for (Method method : getMethods(clazz)) {
            if (mSkipMethods.contains(method.getName())) {
                continue;
            }

            if (Modifier.isPrivate(method.getModifiers()) && !includePrivate) {
                continue;
            }

            hookMethod(printer, clazz, method.getName(), method.getParameters(),
                    method.getReturnType().getName(), expandArrayValue, indents);
        }

        printer.println();
        printer.close();

        return writer.toString();
    }

    private Method[] getMethods(Class clazz) {
        Method[] publicMethods = clazz.getMethods();
        Method[] declaredMethods = clazz.getDeclaredMethods();
        Set<Method> set = new HashSet<>();
        set.addAll(Arrays.asList(publicMethods));
        set.addAll(Arrays.asList(declaredMethods));

        Method[] allMethods = new Method[set.size()];
        set.toArray(allMethods);
        return allMethods;
    }

    private void saveScript(String outputFileName, String script) {
        try {
            PrintWriter writer = new PrintWriter(outputFileName);
            writer.println(script);
            writer.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    private String printArgs() {
        return "function print_args() {\n"
               + "    var str = \"\";\n"
               + "    for (var i = 0; i < arguments.length; i++) {\n"
               + "        str += arguments[i] + \", \";\n"
               + "    }\n"
               + "    return str;\n"
               + "}\n\n";
    }

    private String expandArrays() {
        return "function expand_array(arr) {\n"
               + "    if (arr != null) {\n"
               + "        var str = \"[\";\n"
               + "        for (var i = 0; i < arr.length; i++) {\n"
               + "            str += arr[i] + \", \";\n"
               + "        }\n"
               + "        return str + \"]\";\n"
               + "    } else {\n"
               + "        return \"null\";\n"
               + "    }"
               + "}\n\n";
    }

    private void hookMethod(PrintWriter printer, Class clazz, String name,
            Parameter[] params, String returnType, boolean expandArrayValue, int indents) {
        printIndents(printer, indents);
        printer.println("try {");

        StringBuilder formalParams = new StringBuilder();
        StringBuilder actualParams = new StringBuilder();
        StringBuilder actualParamsToLog = new StringBuilder();
        extractParams(params, expandArrayValue, formalParams, actualParams, actualParamsToLog);

        printIndents(printer, indents + 1);
        String funcName = "func_" + (name.startsWith("$") ? name.substring(1) : name)
                          + "_" + mRandom.nextInt(Integer.MAX_VALUE);
        printer.println(String.format("var %s = %s.%s.overload(%s);",
                funcName, clazz.getSimpleName(), name, formalParams.toString()));

        boolean hasReturn = !returnType.equals("void");
        boolean returnArray = returnType.startsWith("[");

        printIndents(printer, indents + 1);
        printer.println(String.format("%s.implementation = function (%s) {",
                funcName, actualParams.toString()));

        String invokeParams;
        if (actualParams.length() == 0) {
            invokeParams = "this";
        } else {
            invokeParams = "this, " + actualParams.toString();
        }
        if (hasReturn) {
            printIndents(printer, indents + 2);
            printer.println(String.format("var ret = %s.call(%s);", funcName, invokeParams));
        } else {
            printIndents(printer, indents + 2);
            printer.println(String.format("%s.call(%s);", funcName, invokeParams));

            printIndents(printer, indents + 2);
            printer.println("var ret = \"VOID\";");
        }

        String logReturn = returnArray
                ? (expandArrayValue ? "expand_array(ret)" : arrayTypeName(returnType))
                : "ret";
        if (actualParamsToLog.length() == 0) {
            printIndents(printer, indents + 2);
            printer.println(String.format("send(\"%s(\" + this + \").%s: ret=\" + %s);",
                    clazz.getName(), name, logReturn));
        } else {
            printIndents(printer, indents + 2);
            printer.println(String.format(
                    "send(\"%s(\" + this + \").%s: \" + print_args(%s) + \"ret=\" + %s);",
                    clazz.getName(), name, actualParamsToLog.toString(), logReturn));
        }

        if (hasReturn) {
            printIndents(printer, indents + 2);
            printer.println("return ret;");
        }

        printIndents(printer, indents + 1);
        printer.println("};");

        printIndents(printer, indents);
        printer.println("} catch(err) {");

        printIndents(printer, indents + 1);
        printer.println(String.format("send(\"%s.%s hook error: \" + err.message);",
                clazz.getSimpleName(), name));

        printIndents(printer, indents);
        printer.println("}");

        printer.println();
    }

    private void extractParams(Parameter[] parameters, boolean expandArrayValue,
            StringBuilder formalParams, StringBuilder actualParams,
            StringBuilder actualParamsToLog) {
        for (Parameter param : parameters) {
            concat(formalParams, "\"" + param.getType().getName() + "\"");
            concat(actualParams, param.getName());

            if (param.getType().getName().startsWith("[")) {
                // if we print array directly, it will only be printed as `[object Object]`,
                // so let's print it as `type[]`, or expand it.
                if (expandArrayValue) {
                    concat(actualParamsToLog, "expand_array(" + param.getName() + ")");
                } else {
                    concat(actualParamsToLog,
                            "\"" + arrayTypeName(param.getType().getName()) + "\"");
                }
            } else {
                concat(actualParamsToLog, param.getName());
            }
        }
    }

    private void printIndents(PrintWriter printer, int indents) {
        for (int i = 0; i < indents; i++) {
            printer.print(INDENT);
        }
    }

    private String arrayTypeName(String name) {
        if (mArrayNames.containsKey(name)) {
            return mArrayNames.get(name);
        }
        return name.substring(1) + "[]";
    }

    private void concat(StringBuilder builder, String str) {
        builder.append(builder.length() == 0 ? str : ", " + str);
    }
}
