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
import java.util.Set;
import java.util.stream.Stream;

/**
 * Created by Piasy on 02/06/2017.
 */
public class FridaAndroidTracer {
    private static final String INDENT = "    ";

    private static final Map<String, String> ARRAY_NAME_MAP;
    private static final Set<String> SKIP_METHODS;

    static {
        ARRAY_NAME_MAP = new HashMap<>();
        ARRAY_NAME_MAP.put("[Z", "boolean[]");
        ARRAY_NAME_MAP.put("[B", "byte[]");
        ARRAY_NAME_MAP.put("[C", "char[]");
        ARRAY_NAME_MAP.put("[S", "short[]");
        ARRAY_NAME_MAP.put("[I", "int[]");
        ARRAY_NAME_MAP.put("[J", "long[]");
        ARRAY_NAME_MAP.put("[F", "float[]");
        ARRAY_NAME_MAP.put("[D", "double[]");

        SKIP_METHODS = new HashSet<>(
                Arrays.asList("finalize", "wait", "equals", "toString", "hashCode", "getClass",
                        "notify",
                        "notifyAll"));
    }

    public static void main(String[] argv) {
        if (argv.length < 4) {
            printUsage();
            System.exit(1);
        }

        String[] jarFiles = getInputs(argv[0]);
        String[] classNames = getInputs(argv[1]);
        String outputFileName = argv[2];
        String[] skipMethods = getInputs(argv[3]);
        boolean includePrivate = argv.length > 4 && "true".equals(argv[4]);

        SKIP_METHODS.addAll(Arrays.asList(skipMethods));

        StringBuilder script = new StringBuilder();

        script.append("////////// auto-gen hook script\n\n");

        script.append(printArgs());
        script.append("Java.perform(function () {\n");

        ClassLoader classLoader = loadJars(jarFiles);
        if (classLoader == null) {
            System.out.println("Load jar files fail!");
            System.exit(2);
        }

        for (String className : classNames) {
            Class clazz = findClass(classLoader, className);

            if (clazz == null) {
                System.out.println("Class not found: " + className);
                continue;
            }

            script.append(hookClass(clazz, SKIP_METHODS, includePrivate, 1));
        }

        script.append("});\n");

        saveScript(outputFileName, script.toString());
    }

    private static void printUsage() {
        System.out.println("Usage: java -jar FridaAndroidTracer.jar <jar files>"
                           + "<class names> <output script path> <skip methods> <include private>");
        System.out.println("\t jar files:          jar files to be included, "
                           + "in csv format, or @filename");
        System.out.println("\t class names:        classes to be hooked, "
                           + "in csv format, or @filename");
        System.out.println("\t output script path: output script path");
        System.out.println("\t skip methods:       methods to be skipped, "
                           + "in csv format, or @filename");
        System.out.println("\t include private:    optional, \"true\" to include private methods");
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

    private static ClassLoader loadJars(String[] jarFiles) {
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

    private static Class findClass(ClassLoader classLoader, String className) {
        try {
            return classLoader.loadClass(className);
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    private static String hookClass(Class clazz, Set<String> skipMethods, boolean includePrivate,
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
            hookConstructor(printer, clazz, constructor, 1);
        }

        for (Method method : getMethods(clazz)) {
            if (skipMethods.contains(method.getName())) {
                continue;
            }

            if (Modifier.isPrivate(method.getModifiers()) && !includePrivate) {
                continue;
            }

            hookMethod(printer, clazz, method, 1);
        }

        printer.println();
        printer.close();

        return writer.toString();
    }

    private static Method[] getMethods(Class clazz) {
        Method[] publicMethods = clazz.getMethods();
        Method[] declaredMethods = clazz.getDeclaredMethods();
        Set<Method> set = new HashSet<>();
        set.addAll(Arrays.asList(publicMethods));
        set.addAll(Arrays.asList(declaredMethods));

        Method[] allMethods = new Method[set.size()];
        set.toArray(allMethods);
        return allMethods;
    }

    private static void saveScript(String outputFileName, String script) {
        try {
            PrintWriter writer = new PrintWriter(outputFileName);
            writer.println(script);
            writer.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    private static String printArgs() {
        return "function print_args() {\n"
               + "    var str = \"\";\n"
               + "    for (var i = 0; i < arguments.length; i++) {\n"
               + "        str += arguments[i] + \", \";\n"
               + "    }\n"
               + "    return str;\n"
               + "}\n\n";
    }

    private static void hookConstructor(PrintWriter printer, Class clazz, Constructor constructor,
            int indents) {
        printIndents(printer, indents);
        printer.println("try {");

        printIndents(printer, indents + 1);
        printer.print(String.format("%s.$init.overload(", clazz.getSimpleName()));

        StringBuilder params = new StringBuilder();
        StringBuilder paramsToLog = new StringBuilder();
        extractParams(printer, constructor.getParameters(), params, paramsToLog);
        printer.print(String.format(").implementation = function (%s)", params.toString()));

        printer.println(" {");

        if (paramsToLog.length() == 0) {
            printIndents(printer, indents + 2);
            printer.append(String.format("send(\"%s.$init\");", clazz.getName()))
                    .println();
        } else {
            printIndents(printer, indents + 2);
            printer.append(
                    String.format("send(\"%s.$init: \" + print_args(%s));",
                            clazz.getName(), paramsToLog.toString()))
                    .println();
        }

        printIndents(printer, indents + 2);
        printer.append(String.format("return this.$init(%s);", params.toString()))
                .println();

        printIndents(printer, indents + 1);
        printer.println("};");

        printIndents(printer, indents);
        printer.println("} catch(err) {");
        printIndents(printer, indents + 1);
        printer.println("console.log(err.message);");
        printIndents(printer, indents);
        printer.println("}");

        printer.println();
    }

    private static void hookMethod(PrintWriter printer, Class clazz, Method method, int indents) {
        printIndents(printer, indents);
        printer.println("try {");

        printIndents(printer, indents + 1);
        printer.print(String.format("%s.%s.overload(", clazz.getSimpleName(), method.getName()));

        boolean hasReturn = !method.getReturnType().getName().equals("void");

        StringBuilder params = new StringBuilder();
        StringBuilder paramsToLog = new StringBuilder();
        extractParams(printer, method.getParameters(), params, paramsToLog);
        printer.print(String.format(").implementation = function (%s)", params.toString()));

        printer.println(" {");

        if (hasReturn) {
            printIndents(printer, indents + 2);
            printer.append("var ret = this.")
                    .append(method.getName())
                    .append("(")
                    .append(params.toString())
                    .append(");")
                    .println();
        } else {
            printIndents(printer, indents + 2);
            printer.append("this.")
                    .append(method.getName())
                    .append("(")
                    .append(params.toString())
                    .append(");")
                    .println();

            printIndents(printer, indents + 2);
            printer.append("var ret = \"VOID\";")
                    .println();
        }

        if (paramsToLog.length() == 0) {
            printIndents(printer, indents + 2);
            printer.append(String.format("send(\"%s(\" + this + \").%s: ret=\" + ret);",
                    clazz.getName(), method.getName()))
                    .println();
        } else {
            printIndents(printer, indents + 2);
            printer.append(
                    String.format(
                            "send(\"%s(\" + this + \").%s: \" + print_args(%s) + \"ret=\" + ret);",
                            clazz.getName(), method.getName(), paramsToLog.toString()))
                    .println();
        }

        if (hasReturn) {
            printIndents(printer, indents + 2);
            printer.append("return ret;")
                    .println();
        }

        printIndents(printer, indents + 1);
        printer.println("};");

        printIndents(printer, indents);
        printer.println("} catch(err) {");
        printIndents(printer, indents + 1);
        printer.println("console.log(err.message);");
        printIndents(printer, indents);
        printer.println("}");

        printer.println();
    }

    private static void extractParams(PrintWriter printer, Parameter[] parameters,
            StringBuilder params, StringBuilder paramsToLog) {
        for (Parameter param : parameters) {
            String sigFormatter;
            String paramFormatter;
            if (params.length() == 0) {
                sigFormatter = "\"%s\"";
                paramFormatter = "%s";
            } else {
                sigFormatter = ", \"%s\"";
                paramFormatter = ", %s";
            }
            printer.print(String.format(sigFormatter, param.getType().getName()));

            params.append(String.format(paramFormatter, param.getName()));

            if (param.getType().getName().startsWith("[")) {
                paramsToLog.append(asConcat(paramsToLog.length() == 0,
                        String.format("\"%s\"", arrayTypeName(param.getType().getName()))));
            } else {
                paramsToLog.append(asConcat(paramsToLog.length() == 0, param.getName()));
            }
        }
    }

    private static void printIndents(PrintWriter printer, int indents) {
        for (int i = 0; i < indents; i++) {
            printer.print(INDENT);
        }
    }

    private static String arrayTypeName(String name) {
        if (ARRAY_NAME_MAP.containsKey(name)) {
            return ARRAY_NAME_MAP.get(name);
        }
        return name.substring(1) + "[]";
    }

    private static String asConcat(boolean first, String str) {
        return first ? str : ", " + str;
    }
}
