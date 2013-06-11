package org.jmangos.sniffer.utils;

public class ClassUtils {
	 /**
     * Checks if class in member of the package
     * 
     * @param clazz
     *            class to check
     * @param packageName
     *            package
     * @return true if is member
     */
     public static boolean isPackageMember(Class<?> clazz, String packageName)
     {
             return isPackageMember(clazz.getName(), packageName);
     }
     
     /**
     * Checks if classNames belongs to package
     * 
     * @param className
     *            class name
     * @param packageName
     *            package
     * @return true if belongs
     */
     public static boolean isPackageMember(String className, String packageName)
     {
             if(!className.contains("."))
             {
                     return packageName == null || packageName.isEmpty();
             }
             else
             {
                     String classPackage = className.substring(0, className.lastIndexOf('.'));
                     return packageName.equals(classPackage);
             }
     }
}
