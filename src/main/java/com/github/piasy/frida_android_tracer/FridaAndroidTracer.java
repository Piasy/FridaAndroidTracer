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

/**
 * Created by Piasy on 02/06/2017.
 */
public class FridaAndroidTracer {
    private static final String INDENT = "    ";

    private static final Map<String, String> ARRAY_NAME_MAP;
    private static final Set<String> SKIP_METHODS;
    private static final Random RANDOM = new Random(System.currentTimeMillis());

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

        ClassLoader classLoader = loadJars(jarFiles);
        if (classLoader == null) {
            System.out.println("Load jar files fail!");
            System.exit(2);
        }

        StringBuilder script = new StringBuilder();

        script.append("////////// auto-gen hook script\n\n");
        script.append(printArgs());
        script.append("Java.perform(function () {\n");

        for (String className : classNames) {
            Class clazz = findClass(classLoader, className);

            if (clazz == null) {
                System.out.println("Class not found: " + className);
                continue;
            }

            script.append(hookClass(clazz, SKIP_METHODS, includePrivate, 1));
        }

        script.append(INDENT)
                .append("send(\"Hook started!\");\n");
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
            hookMethod(printer, clazz, "$init", constructor.getParameters(), clazz.getSimpleName(),
                    indents);
        }

        for (Method method : getMethods(clazz)) {
            if (skipMethods.contains(method.getName())) {
                continue;
            }

            if (Modifier.isPrivate(method.getModifiers()) && !includePrivate) {
                continue;
            }

            hookMethod(printer, clazz, method.getName(), method.getParameters(),
                    method.getReturnType().getName(), indents);
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

    private static void hookMethod(PrintWriter printer, Class clazz, String name,
            Parameter[] params, String returnType, int indents) {
        printIndents(printer, indents);
        printer.println("try {");

        StringBuilder formalParams = new StringBuilder();
        StringBuilder actualParams = new StringBuilder();
        StringBuilder actualParamsToLog = new StringBuilder();
        extractParams(params, formalParams, actualParams, actualParamsToLog);

        printIndents(printer, indents + 1);
        String funcName = "func_" + (name.startsWith("$") ? name.substring(1) : name)
                          + "_" + RANDOM.nextInt(Integer.MAX_VALUE);
        printer.print(String.format("var %s = %s.%s.overload(%s);", funcName, clazz.getSimpleName(),
                name, formalParams.toString()));
        printer.println();

        boolean hasReturn = !returnType.equals("void");

        printIndents(printer, indents + 1);
        printer.print(String.format("%s.implementation = function (%s) {", funcName,
                actualParams.toString()));
        printer.println();

        if (hasReturn) {
            printIndents(printer, indents + 2);
            printer.append("var ret = ")
                    .append(funcName)
                    .append(".call(this")
                    .append(actualParams.length() == 0 ? "" : (", " + actualParams.toString()))
                    .append(");")
                    .println();
        } else {
            printIndents(printer, indents + 2);
            printer.append(funcName)
                    .append(".call(this")
                    .append(actualParams.length() == 0 ? "" : (", " + actualParams.toString()))
                    .append(");")
                    .println();

            printIndents(printer, indents + 2);
            printer.append("var ret = \"VOID\";")
                    .println();
        }

        if (actualParamsToLog.length() == 0) {
            printIndents(printer, indents + 2);
            printer.append(String.format("send(\"%s(\" + this + \").%s: ret=\" + ret);",
                    clazz.getName(), name))
                    .println();
        } else {
            printIndents(printer, indents + 2);
            printer.append(
                    String.format(
                            "send(\"%s(\" + this + \").%s: \" + print_args(%s) + \"ret=\" + ret);",
                            clazz.getName(), name, actualParamsToLog.toString()))
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

    private static void extractParams(Parameter[] parameters, StringBuilder formalParams,
            StringBuilder actualParams, StringBuilder actualParamsToLog) {
        for (Parameter param : parameters) {
            concat(formalParams, "\"" + param.getType().getName() + "\"");
            concat(actualParams, param.getName());

            if (param.getType().getName().startsWith("[")) {
                concat(actualParamsToLog, "\"" + arrayTypeName(param.getType().getName()) + "\"");
            } else {
                concat(actualParamsToLog, param.getName());
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

    private static void concat(StringBuilder builder, String str) {
        builder.append(builder.length() == 0 ? str : ", " + str);
    }
}
