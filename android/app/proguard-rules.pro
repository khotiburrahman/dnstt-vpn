-keep class go.** { *; }
-keep class mobile.** { *; }
-keep class **$$Bridge { *; }
-keepclasseswithmembers class * {
    native <methods>;
}
